#include "log.h"
#include "cov.h"
#include "cmplog.h"
#include <sys/shm.h>

struct cmp_map *__afl_cmp_map = NULL;
unsigned long *fuzz_cursor = NULL;
unsigned long cov_prev_loc = 0;
unsigned long cov_prev_prev_loc = 0;
unsigned char *cov_area_ptr = NULL;
unsigned long cov_area_size = 0;

/* Ensure a meaningful power of 2 */
static int check_bitmap_size(uint32_t size) {
    for(uint32_t valid = COV_AREA_SIZE_MIN; valid <= COV_AREA_SIZE_MAX; valid<<=1) {
        if(size == valid) {
            return true;
        }
    }
    return false;
}

void fuzzer_init_cov(uc_engine *uc, void *bitmap_region, uint32_t bitmap_size) {
    if(bitmap_size == 0) {
        bitmap_size = COV_AREA_SIZE_MAX;
    }

    /* As soon as MAP_SIZE is not enforced, also sync this in afl_add_instrumentation */
    FW_ASSERT1(cov_area_ptr == NULL && check_bitmap_size(bitmap_size));

    if(bitmap_region == NULL) {
        cov_area_ptr = malloc(bitmap_size);
    } else {
        cov_area_ptr = bitmap_region;
    }

    cov_area_size = bitmap_size;
    cov_prev_prev_loc = 0;
    cov_prev_loc = 0;

    if (getenv("___AFL_EINS_ZWEI_POLIZEI___")) {  // CmpLog forkserver
        char* id_str = getenv(CMPLOG_SHM_ENV_VAR);
        if (id_str) {
            uint32_t shm_id = atoi(id_str);
            __afl_cmp_map = shmat(shm_id, NULL, 0);
            if (__afl_cmp_map == (void *)-1){
                printf("Failed to get RQ map, exiting\n");
                exit(1);
            }
        }
    }
}

void fuzzer_reset_cov(uc_engine *uc, int do_clear) {
    if(do_clear && cov_area_ptr) {
        memset(cov_area_ptr, 0, cov_area_size);
    }

    cov_prev_prev_loc = 0;
    cov_prev_loc = 0;
    if(__afl_cmp_map){
        memset(__afl_cmp_map, 0, sizeof(struct cmp_map));
    }
}

void fuzzer_cursor(uc_engine *uc, long* cursor){
    fuzz_cursor = cursor;
}
