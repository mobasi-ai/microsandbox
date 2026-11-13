// A hostile virtio-mem driver that runs in guest user space as root.
//
// The wrapper script takes the virtio-mem device from the kernel. This program then drives the
// device registers through /dev/mem, on the real hypervisor. It sends requests that a correct
// driver never sends, checks each answer against a model, reads and writes memory that is not
// plugged, and races memory access against plug and unplug.
//
// Build in the guest: gcc -O2 -pthread -o hostile hostile.c
// Usage: hostile <mmio base, hex> <mode> [arguments]
//   info               print the device configuration
//   model STEPS SEED   random requests, checked against a model, with data checks
//   touch              read and write a block that was never plugged, then one after an unplug
//   race SECONDS       one thread plugs and unplugs a block while another reads and writes it
//                      all the time, also when it is not plugged
//   racesafe SECONDS   the same, but the other thread stops before each unplug, as a correct
//                      driver does: each access must find memory, and the memory must hold data
//   ringmove           put the virtqueue and its buffers in a plugged block, then unplug that
//                      block through the same queue
//   resetloop COUNT    reset and start the device COUNT times; the memory of the VMM process
//                      must not grow without limit (the caller measures it)
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define BLOCK (2ull << 20)
#define QUEUE 8
enum { PLUG = 0, UNPLUG = 1, UNPLUG_ALL = 2, STATE = 3 };
enum { ACK = 0, NACK = 1, BUSY = 2, ERROR = 3 };
static const char *resp_name[] = {"ACK", "NACK", "BUSY", "ERROR"};

struct desc { uint64_t addr; uint32_t len; uint16_t flags, next; };
struct avail { uint16_t flags, idx, ring[QUEUE], used_event; };
struct used_elem { uint32_t id, len; };
struct used { uint16_t flags, idx; struct used_elem ring[QUEUE]; };
struct req { uint16_t type, pad[3]; uint64_t addr; uint16_t nb, pad2[3]; };
struct resp { uint16_t type, pad[3], state; } __attribute__((packed));

static volatile uint32_t *reg;
static int devmem;
static struct desc *desc;
static struct avail *avail;
static struct used *used;
static struct req *request;
static struct resp *response;
static uint64_t request_phys, response_phys;
static uint16_t avail_idx;
static uint64_t region_addr, region_size, requested_size;
static uint64_t blocks;
static volatile uint64_t *memory; // the hotplug region, mapped from /dev/mem
static int unplugged_inaccessible;

static void die(const char *what) { perror(what); exit(2); }
#define R(off) reg[(off) / 4]

static uint64_t phys_of(void *va) {
  uint64_t entry;
  int fd = open("/proc/self/pagemap", O_RDONLY);
  if (fd < 0) die("pagemap");
  if (pread(fd, &entry, 8, ((uintptr_t)va / 4096) * 8) != 8) die("pagemap read");
  close(fd);
  if (!(entry >> 63)) { fprintf(stderr, "page is not present\n"); exit(2); }
  return (entry & ((1ull << 55) - 1)) * 4096 + ((uintptr_t)va & 4095);
}

static uint64_t config64(unsigned offset) {
  return (uint64_t)R(0x100 + offset) | ((uint64_t)R(0x104 + offset) << 32);
}

static void read_config(void) {
  region_addr = config64(16);
  region_size = config64(24);
  requested_size = config64(48);
  blocks = region_size / BLOCK;
}

// Reset the device and give it a virtqueue. `queue` holds the descriptor table and the rings,
// `buffers` holds the request and the response. Both are one page, at the given guest-physical
// addresses.
static void handshake(uint8_t *queue, uint64_t queue_phys, uint8_t *buffers, uint64_t buffers_phys) {
  // Not memset: on arm64 it can use an instruction that is not permitted on a /dev/mem mapping.
  for (int i = 0; i < 4096; i += 8) {
    *(volatile uint64_t *)(queue + i) = 0;
    *(volatile uint64_t *)(buffers + i) = 0;
  }
  desc = (void *)queue;
  avail = (void *)(queue + 0x100);
  used = (void *)(queue + 0x200);
  request = (void *)buffers;
  response = (void *)(buffers + 0x100);
  request_phys = buffers_phys;
  response_phys = buffers_phys + 0x100;
  avail_idx = 0;
  // The device takes one status flag for each write.
  R(0x070) = 0;
  R(0x070) = 1;
  R(0x070) = 1 | 2;
  R(0x014) = 0; uint32_t low = R(0x010);
  R(0x014) = 1; uint32_t high = R(0x010);
  unplugged_inaccessible = (low >> 1) & 1;
  R(0x024) = 0; R(0x020) = low & 2;
  R(0x024) = 1; R(0x020) = high & 1;
  R(0x070) = 1 | 2 | 8;
  if (!(R(0x070) & 8)) { fprintf(stderr, "the device refused the features\n"); exit(2); }
  R(0x030) = 0;
  if (R(0x034) < QUEUE) { fprintf(stderr, "queue too small\n"); exit(2); }
  R(0x038) = QUEUE;
  R(0x080) = (uint32_t)queue_phys; R(0x084) = queue_phys >> 32;
  R(0x090) = (uint32_t)(queue_phys + 0x100); R(0x094) = (queue_phys + 0x100) >> 32;
  R(0x0a0) = (uint32_t)(queue_phys + 0x200); R(0x0a4) = (queue_phys + 0x200) >> 32;
  R(0x044) = 1;
  R(0x070) = 1 | 2 | 8 | 4;
}

static uint8_t *own_pages;

// A queue in two locked pages of this program. Their guest-physical addresses come from the
// page map.
static void own_queue(void) {
  handshake(own_pages, phys_of(own_pages), own_pages + 4096, phys_of(own_pages + 4096));
}

static void setup(uint64_t base) {
  devmem = open("/dev/mem", O_RDWR | O_SYNC);
  if (devmem < 0) die("/dev/mem");
  reg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, devmem, base);
  if (reg == MAP_FAILED) die("mmap of the device registers");
  if (R(0x000) != 0x74726976 || R(0x008) != 24) {
    fprintf(stderr, "not a virtio-mem device: magic=%x id=%u\n", R(0x000), R(0x008));
    exit(2);
  }
  own_pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED | MAP_POPULATE, -1, 0);
  if (own_pages == MAP_FAILED) die("mmap of the queue pages");
  memset(own_pages, 0, 8192);
  own_queue();
  read_config();
  memory = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_SHARED, devmem, region_addr);
  if (memory == MAP_FAILED) { perror("mmap of the hotplug region (no data checks)"); memory = NULL; }
}

// Send one request and wait for the answer. Returns the response type, or -1 on a timeout.
static int send_at(uint16_t type, uint64_t addr, uint16_t nb, uint16_t *state,
                   uint64_t req_phys, uint64_t resp_phys) {
  request->type = type; request->addr = addr; request->nb = nb;
  response->type = 0xffff; response->state = 0xffff;
  desc[0] = (struct desc){req_phys, 24, 1, 1};
  desc[1] = (struct desc){resp_phys, 10, 2, 0};
  avail->ring[avail_idx % QUEUE] = 0;
  __sync_synchronize();
  avail->idx = ++avail_idx;
  __sync_synchronize();
  R(0x050) = 0;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (used->idx != avail_idx) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - start.tv_sec > 20) return -1;
    __sync_synchronize();
  }
  R(0x064) = R(0x060);
  if (state) *state = response->state;
  return response->type;
}

static int send(uint16_t type, uint64_t addr, uint16_t nb, uint16_t *state) {
  return send_at(type, addr, nb, state, request_phys, response_phys);
}

static uint64_t rng_state;
static uint64_t rng(void) {
  rng_state ^= rng_state >> 12; rng_state ^= rng_state << 25; rng_state ^= rng_state >> 27;
  return rng_state * 0x2545f4914f6cdd1dull;
}

static volatile uint64_t *tag_at(uint64_t block, int which) {
  static const uint64_t offsets[3] = {0, BLOCK / 2, BLOCK - 8};
  return (volatile uint64_t *)((uintptr_t)memory + block * BLOCK + offsets[which]);
}

// Random requests against a model. The device must answer as the model says, on the real
// hypervisor: a plugged block is zero at first and keeps its data, and a hostile address or
// count changes nothing.
static int model(uint64_t steps, uint64_t seed) {
  uint8_t *plugged = calloc(blocks, 1);
  uint64_t *tags = calloc(blocks, 8);
  uint64_t count = 0, acks = 0, nacks = 0, busy = 0, errors = 0, bad = 0;
  rng_state = seed ? seed : 1;
  if (send(UNPLUG_ALL, 0, 0, NULL) != ACK) { printf("FAIL: first UNPLUG_ALL\n"); return 1; }
  for (uint64_t step = 0; step < steps && bad < 10; step++) {
    uint64_t value = rng();
    uint16_t type = (value % 16 < 7) ? PLUG : (value % 16 < 13) ? UNPLUG
                  : (value % 16 == 13) ? STATE : (value % 16 == 14) ? UNPLUG_ALL : 4 + (value >> 8) % 60000;
    uint64_t block = (value >> 16) % blocks;
    uint64_t addr;
    switch ((value >> 32) % 16) {
      case 11: addr = region_addr + region_size + ((value >> 40) % 2) * BLOCK; break;
      case 12: case 13: addr = region_addr + block * BLOCK + 1 + ((value >> 40) % 256) * 16; break;
      case 14: addr = region_addr - (1 + (value >> 40) % 256) * BLOCK; break;
      case 15: addr = rng(); break;
      default: addr = region_addr + block * BLOCK;
    }
    uint16_t nb;
    switch ((value >> 48) % 16) {
      case 12: nb = 0; break;
      case 13: nb = rng(); break;
      case 14: case 15: nb = blocks - 1 + (value >> 52) % 3; break;
      default: nb = 1 + (value >> 52) % 4;
    }
    read_config();
    // The model: wide arithmetic, apart from the device code.
    __int128 offset = (__int128)addr - region_addr;
    int valid = nb != 0 && offset >= 0 && offset % BLOCK == 0 && offset / BLOCK + nb <= blocks;
    uint64_t first = valid ? offset / BLOCK : 0;
    int expect, any_plugged = 0, all_plugged = 1;
    if (valid) for (uint64_t b = first; b < first + nb; b++) { any_plugged |= plugged[b]; all_plugged &= plugged[b]; }
    uint16_t expect_state = 0;
    if (type == PLUG) expect = !valid ? ERROR : ((count + nb) * BLOCK > requested_size || any_plugged) ? NACK : ACK;
    else if (type == UNPLUG) expect = !valid ? ERROR : !all_plugged ? NACK : ACK;
    else if (type == UNPLUG_ALL) expect = ACK;
    else if (type == STATE) { expect = !valid ? ERROR : ACK; expect_state = all_plugged ? 0 : !any_plugged ? 1 : 2; }
    else expect = ERROR;

    if (memory && type == UNPLUG && expect == ACK)
      for (uint64_t b = first; b < first + nb; b++)
        for (int i = 0; i < 3; i++)
          if (*tag_at(b, i) != tags[b]) { bad++; printf("BAD step %llu: block %llu lost its data\n", (unsigned long long)step, (unsigned long long)b); }

    uint16_t state = 0;
    int got = send(type, addr, nb, &state);
    if (got < 0) { printf("FAIL step %llu: no answer\n", (unsigned long long)step); return 1; }
    // BUSY is a correct answer when the host cannot give or take memory now. Nothing changed,
    // except that UNPLUG_ALL can have released some runs: ask the device for the state.
    if (got == BUSY && (type == PLUG || type == UNPLUG || type == UNPLUG_ALL) && expect == ACK) {
      busy++;
      if (type == UNPLUG_ALL) {
        count = 0;
        for (uint64_t b = 0; b < blocks; b++) {
          uint16_t s = 9;
          send(STATE, region_addr + b * BLOCK, 1, &s);
          plugged[b] = s == 0; count += plugged[b]; if (!plugged[b]) tags[b] = 0;
        }
      }
      continue;
    }
    if (got != expect || (type == STATE && got == ACK && state != expect_state)) {
      bad++;
      printf("BAD step %llu: type %u addr 0x%llx nb %u: got %s state %u, expected %s state %u\n",
             (unsigned long long)step, type, (unsigned long long)addr, nb, resp_name[got & 3], state, resp_name[expect], expect_state);
      continue;
    }
    if (got == ACK) acks++; else if (got == NACK) nacks++; else errors++;
    if (got != ACK) continue;
    if (type == PLUG) {
      for (uint64_t b = first; b < first + nb; b++) {
        plugged[b] = 1; count++;
        tags[b] = rng() | 1;
        if (memory) for (int i = 0; i < 3; i++) {
          if (*tag_at(b, i) != 0) { bad++; printf("BAD step %llu: plugged block %llu is not zero\n", (unsigned long long)step, (unsigned long long)b); }
          *tag_at(b, i) = tags[b];
        }
      }
    } else if (type == UNPLUG) {
      for (uint64_t b = first; b < first + nb; b++) {
        plugged[b] = 0; count--; tags[b] = 0;
        // Where unplugged memory can be read, it must be zero.
        if (memory && !unplugged_inaccessible)
          for (int i = 0; i < 3; i++)
            if (*tag_at(b, i) != 0) { bad++; printf("BAD step %llu: unplugged block %llu is not zero\n", (unsigned long long)step, (unsigned long long)b); }
      }
    } else if (type == UNPLUG_ALL) {
      memset(plugged, 0, blocks); memset(tags, 0, blocks * 8); count = 0;
    }
    // All plugged blocks keep their data, also the neighbors of the block of this request.
    if (memory && step % 64 == 0)
      for (uint64_t b = 0; b < blocks; b++)
        if (plugged[b]) for (int i = 0; i < 3; i++)
          if (*tag_at(b, i) != tags[b]) { bad++; printf("BAD step %llu: block %llu changed\n", (unsigned long long)step, (unsigned long long)b); }
  }
  send(UNPLUG_ALL, 0, 0, NULL);
  printf("model: steps=%llu acks=%llu nacks=%llu busy=%llu errors=%llu bad=%llu data_checks=%s\n",
         (unsigned long long)steps, (unsigned long long)acks, (unsigned long long)nacks,
         (unsigned long long)busy, (unsigned long long)errors, (unsigned long long)bad, memory ? "yes" : "no");
  return bad != 0;
}

// Read and write memory that is not plugged. A host that keeps the region mapped gives zero
// pages. A host that does not (Windows) must stop this VM, and nothing else.
static int touch(void) {
  if (!memory) { printf("touch: cannot map the hotplug region\n"); return 1; }
  send(UNPLUG_ALL, 0, 0, NULL);
  printf("touch: unplugged_inaccessible=%d\n", unplugged_inaccessible);
  printf("touch: plug block 1, write, unplug\n"); fflush(stdout);
  if (send(PLUG, region_addr + BLOCK, 1, NULL) != ACK) { printf("FAIL: plug\n"); return 1; }
  *tag_at(1, 0) = 0x1122334455667788ull;
  if (*tag_at(1, 0) != 0x1122334455667788ull) { printf("FAIL: plugged memory does not hold data\n"); return 1; }
  if (send(UNPLUG, region_addr + BLOCK, 1, NULL) != ACK) { printf("FAIL: unplug\n"); return 1; }
  printf("touch: read the unplugged block now\n"); fflush(stdout);
  uint64_t after = *tag_at(1, 0);
  printf("touch: unplugged block reads 0x%llx\n", (unsigned long long)after); fflush(stdout);
  uint64_t never = *tag_at(3, 0);
  printf("touch: never-plugged block reads 0x%llx\n", (unsigned long long)never); fflush(stdout);
  *tag_at(3, 1) = 0xdeadbeef;
  printf("touch: wrote a never-plugged block\n"); fflush(stdout);
  // The device must still answer, and a plug must give zero memory.
  if (send(PLUG, region_addr + 3 * BLOCK, 1, NULL) != ACK) { printf("FAIL: plug after touch\n"); return 1; }
  uint64_t replug = *tag_at(3, 1);
  printf("touch: after a plug the block reads 0x%llx\n", (unsigned long long)replug);
  send(UNPLUG_ALL, 0, 0, NULL);
  if (after != 0 || never != 0) { printf("FAIL: unplugged memory is not zero\n"); return 1; }
  printf("touch: done\n");
  return 0;
}

static volatile int stop_race;
static volatile uint64_t touches;
static void *toucher(void *arg) {
  (void)arg;
  volatile uint64_t *at = tag_at(2, 1);
  while (!stop_race) { *at = *at + 1; touches++; }
  return NULL;
}

// One thread plugs and unplugs a block as fast as it can. Another thread reads and writes the
// same block all the time. The device must answer each request, and the host must stay well.
static int race(unsigned seconds) {
  if (!memory) { printf("race: cannot map the hotplug region\n"); return 1; }
  send(UNPLUG_ALL, 0, 0, NULL);
  pthread_t thread;
  pthread_create(&thread, NULL, toucher, NULL);
  uint64_t cycles = 0, refused = 0;
  time_t end = time(NULL) + seconds;
  while (time(NULL) < end) {
    int a = send(PLUG, region_addr + 2 * BLOCK, 1, NULL);
    int b = send(UNPLUG, region_addr + 2 * BLOCK, 1, NULL);
    if (a < 0 || b < 0) { printf("FAIL: no answer after %llu cycles\n", (unsigned long long)cycles); return 1; }
    if (a != ACK || b != ACK) refused++;
    cycles++;
  }
  stop_race = 1;
  pthread_join(thread, NULL);
  // The other thread wrote the block while it was not plugged. Where the host keeps the region
  // mapped, that data stays until an unplug zeroes it. Leave the block clean for later runs.
  send(PLUG, region_addr + 2 * BLOCK, 1, NULL);
  send(UNPLUG_ALL, 0, 0, NULL);
  printf("race: cycles=%llu refused=%llu touches=%llu\n", (unsigned long long)cycles,
         (unsigned long long)refused, (unsigned long long)touches);
  return 0;
}

static volatile int allowed, inside;
static volatile uint64_t wrong;
static void *careful_toucher(void *arg) {
  (void)arg;
  volatile uint64_t *at = tag_at(2, 1);
  uint64_t value = 1;
  while (!stop_race) {
    if (!allowed) continue;
    inside = 1;
    __sync_synchronize();
    if (allowed) {
      *at = value;
      if (*at != value) wrong++;
      value++;
      touches++;
    }
    inside = 0;
    __sync_synchronize();
  }
  return NULL;
}

// As a correct driver: the other thread uses the block only between the answer to a plug and
// the next unplug request. Each access must find memory that holds what was written, on every
// host, with no fault and no lost write.
static int racesafe(unsigned seconds) {
  if (!memory) { printf("racesafe: cannot map the hotplug region\n"); return 1; }
  send(UNPLUG_ALL, 0, 0, NULL);
  pthread_t thread;
  pthread_create(&thread, NULL, careful_toucher, NULL);
  uint64_t cycles = 0, refused = 0, not_zero = 0;
  time_t end = time(NULL) + seconds;
  while (time(NULL) < end) {
    if (send(PLUG, region_addr + 2 * BLOCK, 1, NULL) != ACK) { refused++; continue; }
    if (*tag_at(2, 1) != 0) not_zero++;
    allowed = 1;
    __sync_synchronize();
    for (volatile int spin = 0; spin < (int)(cycles % 2000); spin++) {}
    allowed = 0;
    __sync_synchronize();
    while (inside) {}
    int b = send(UNPLUG, region_addr + 2 * BLOCK, 1, NULL);
    if (b < 0) { printf("FAIL: no answer after %llu cycles\n", (unsigned long long)cycles); return 1; }
    if (b != ACK) refused++;
    cycles++;
  }
  stop_race = 1;
  pthread_join(thread, NULL);
  send(UNPLUG_ALL, 0, 0, NULL);
  printf("racesafe: cycles=%llu refused=%llu touches=%llu wrong=%llu not_zero=%llu\n",
         (unsigned long long)cycles, (unsigned long long)refused, (unsigned long long)touches,
         (unsigned long long)wrong, (unsigned long long)not_zero);
  return wrong != 0 || not_zero != 0;
}

// The virtqueue and its buffers are in a plugged block, and a request through that queue
// unplugs the block. The device must then write its answer and the used ring to memory that it
// has just released. A host that keeps the region mapped writes to the new zero pages. On
// Windows the host memory is gone, and the VMM process ends with an access violation: the VM
// dies, and nothing else.
static int ringmove(void) {
  if (!memory) { printf("ringmove: cannot map the hotplug region\n"); return 1; }
  send(UNPLUG_ALL, 0, 0, NULL);
  if (send(PLUG, region_addr + 5 * BLOCK, 1, NULL) != ACK) { printf("FAIL: plug\n"); return 1; }
  uint8_t *block = (uint8_t *)(uintptr_t)memory + 5 * BLOCK;
  handshake(block, region_addr + 5 * BLOCK, block + 4096, region_addr + 5 * BLOCK + 4096);
  uint16_t state = 9;
  int got = send(STATE, region_addr + 5 * BLOCK, 1, &state);
  printf("ringmove: a request through a queue in block 5: %s, state %u\n", got < 0 ? "no answer" : resp_name[got & 3], state);
  printf("ringmove: unplug block 5 through that queue now\n"); fflush(stdout);
  got = send(UNPLUG, region_addr + 5 * BLOCK, 1, NULL);
  printf("ringmove: the unplug answered %s\n", got < 0 ? "nothing" : resp_name[got & 3]); fflush(stdout);
  // Back to a queue in memory of this program. The device must still work.
  own_queue();
  got = send(STATE, region_addr + 5 * BLOCK, 1, &state);
  printf("ringmove: after it, block 5 is %s (%s)\n", state == 1 ? "unplugged" : state == 0 ? "plugged" : "?", got < 0 ? "no answer" : resp_name[got & 3]);
  send(UNPLUG_ALL, 0, 0, NULL);
  if (got != ACK) { printf("FAIL: the device does not answer\n"); return 1; }
  printf("ringmove: done\n");
  return 0;
}

static int resetloop(uint64_t count) {
  for (uint64_t i = 0; i < count; i++) own_queue();
  uint16_t state = 9;
  int got = send(STATE, region_addr, 1, &state);
  printf("resetloop: %llu resets, then the device answers %s\n", (unsigned long long)count,
         got < 0 ? "nothing" : resp_name[got & 3]);
  return got != ACK;
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: hostile <mmio base> info|model|touch|race|racesafe|ringmove ...\n"); return 2; }
  setup(strtoull(argv[1], NULL, 16));
  printf("device: region 0x%llx size %llu MiB (%llu blocks), requested %llu MiB, plugged %llu MiB, unplugged_inaccessible=%d\n",
         (unsigned long long)region_addr, (unsigned long long)(region_size >> 20), (unsigned long long)blocks,
         (unsigned long long)(requested_size >> 20), (unsigned long long)(config64(40) >> 20), unplugged_inaccessible);
  fflush(stdout);
  if (!strcmp(argv[2], "info")) return 0;
  if (!strcmp(argv[2], "model")) return model(argc > 3 ? strtoull(argv[3], NULL, 0) : 10000, argc > 4 ? strtoull(argv[4], NULL, 0) : 1);
  if (!strcmp(argv[2], "touch")) return touch();
  if (!strcmp(argv[2], "race")) return race(argc > 3 ? atoi(argv[3]) : 10);
  if (!strcmp(argv[2], "racesafe")) return racesafe(argc > 3 ? atoi(argv[3]) : 10);
  if (!strcmp(argv[2], "ringmove")) return ringmove();
  if (!strcmp(argv[2], "resetloop")) return resetloop(argc > 3 ? strtoull(argv[3], NULL, 0) : 100000);
  return 2;
}
