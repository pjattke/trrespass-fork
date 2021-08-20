#include "addr-mapper.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

static size_t g_rmap_len = 0;
static size_t g_base_row = 0;
static size_t g_bks = 0;
static size_t g_rows = 0;

RowMap get_row_map(ADDRMapper * mapper, DRAMAddr * d_addr)
{
//	printf("d_addr->row = %" PRIu64 "\n", d_addr->row);
//	printf("g_base_row = %zu\n", g_base_row);
//	printf("get_banks_cnt() = %" PRIu64 "\n", get_banks_cnt());
//	printf("d_addr->bank = %" PRIu64 "\n", d_addr->bank);
//	printf("g_bks = %zu\n", g_bks);
//	printf("g_rows = %zu\n", g_rows);
  int factor = (g_base_row > d_addr->row) ? 0 : (d_addr->row - g_base_row);
	size_t idx = factor * get_banks_cnt() + d_addr->bank;
//	printf("idx = %zu\n\n", idx);
	assert(idx < g_bks * g_rows);
	return mapper->row_maps[idx];
}

DRAM_pte get_dram_pte(ADDRMapper * mapper, DRAMAddr * d_addr)
{
	RowMap rmap = get_row_map(mapper, d_addr);
	return rmap.lst[(d_addr->col) >> 6];
}

RowMap gen_row_map(DRAMAddr d_src, MemoryBuffer * mem)
{
	RowMap rmap;
	DRAM_pte *dst = (DRAM_pte *) malloc(sizeof(DRAM_pte) * g_rmap_len);
	d_src.col = 0;

	for (size_t col = 0; col < g_rmap_len; col++, d_src.col += (1 << 6)) {
		dst[col].d_addr = d_src;
		dst[col].v_addr = phys_2_virt(dram_2_phys(d_src), mem);
	}
	rmap.lst = dst;
	rmap.len = g_rmap_len;
	return rmap;

}

size_t rmap_idx(size_t bk, size_t row)
{
	return row * get_banks_cnt() + bk;
}

void init_addr_mapper(ADDRMapper * mapper, MemoryBuffer * mem,
		      DRAMAddr * d_base, size_t h_rows)
{
	mapper->row_maps =
	    (RowMap *) malloc(sizeof(RowMap) * h_rows * get_banks_cnt());
	mapper->base_row = d_base->row;
	g_base_row = d_base->row;
	g_bks = get_banks_cnt();
	g_rows = h_rows;
	// set global rmap_len
	g_rmap_len = ROW_SIZE / CL_SIZE;

  	printf("mapper->base_row = %" PRIu64 "\n", mapper->base_row);
	printf("g_base_row = %zu\n", g_base_row);
	printf("get_banks_cnt() = %" PRIu64 "\n", get_banks_cnt());
	printf("g_rows = %" PRIu64 "\n", h_rows);
//	printf("g_bks = %zu\n", g_bks);
//	printf("g_rows = %zu\n", g_rows);

	// create ptes list for every
	DRAMAddr d_tmp = {.bank = 0,.row = 0,.col = 0 };
	for (size_t bk = 0; bk < get_banks_cnt(); bk++) {
		d_tmp.bank = bk;
		for (size_t row = 0; row < h_rows; row++) {
			d_tmp.row = g_base_row + row;
			mapper->row_maps[rmap_idx(bk, row)] =
			    gen_row_map(d_tmp, mem);
		}
	}
}

void tear_down_addr_mapper(ADDRMapper * mapper)
{
	for (int i = 1; i < g_rows * g_bks; i++) {
		free(mapper->row_maps[i].lst);
	}
	free(mapper->row_maps);
}
