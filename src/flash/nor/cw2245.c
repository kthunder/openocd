// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   Copyright (C) 2011 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/cortex_m.h>

#include "cw2245.h"
#include <helper/time_support.h>
/* timeout values */

#define FLASH_WRITE_TIMEOUT 10
#define FLASH_ERASE_TIMEOUT 100

#define PROGRAM_BKPT_OFFSET 0x0c
#define PROGRAM_ARGS_OFFSET 0x10

struct cw2245_options
{
	uint8_t rdp;
	uint8_t user;
	uint16_t data;
	uint32_t protection;
};

struct cw2245_flash_bank
{
	struct cw2245_options option_bytes;
	int ppage_size;
	bool probed;

	bool has_dual_banks;
	/* used to access dual flash bank stm32xl */
	bool can_load_options;
	uint32_t register_base;
	uint8_t default_rdp;
	int user_data_offset;
	int option_offset;
	uint32_t user_bank_size;
};

static int cw2245_load_flash_algo(struct target *target, struct working_area **flash_algorithm);
static int cw2245_mass_erase(struct flash_bank *bank);
static int cw2245_write_block(struct flash_bank *bank, const uint8_t *buffer,
							  uint32_t address, uint32_t hwords_count);

/* flash bank stm32x <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(cw2245_flash_bank_command)
{
	// log_info("%s", __func__);
	struct cw2245_flash_bank *cw2245_info;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	cw2245_info = malloc(sizeof(struct cw2245_flash_bank));

	bank->driver_priv = cw2245_info;
	cw2245_info->probed = false;
	cw2245_info->has_dual_banks = false;
	cw2245_info->can_load_options = false;
	cw2245_info->register_base = FLASH_REG_BASE_B0;
	cw2245_info->user_bank_size = bank->size;

	/* The flash write must be aligned to a halfword boundary */
	bank->write_start_alignment = bank->write_end_alignment = 2;

	return ERROR_OK;
}

static inline int cw2245_get_flash_reg(struct flash_bank *bank, uint32_t reg)
{
	struct cw2245_flash_bank *cw2245_info = bank->driver_priv;
	return reg + cw2245_info->register_base;
}

static inline int cw2245_get_flash_status(struct flash_bank *bank, uint32_t *status)
{
	struct target *target = bank->target;
	return target_read_u32(target, cw2245_get_flash_reg(bank, EFLASH_WR_STT), status);
}

static int cw2245_wait_status_busy(struct flash_bank *bank, int timeout)
{
	struct target *target = bank->target;
	uint32_t status;
	int retval = ERROR_OK;

	/* wait for busy to clear */
	for (;;)
	{
		retval = cw2245_get_flash_status(bank, &status);
		if (retval != ERROR_OK)
			return retval;
		LOG_DEBUG("status: 0x%" PRIx32 "", status);
		if ((status & REG_EFLASH_CTRL_FSM_BSY_MASK) == 0)
			break;
		if (timeout-- <= 0)
		{
			LOG_ERROR("timed out waiting for flash");
			return ERROR_FLASH_BUSY;
		}
		alive_sleep(1);
	}

	return retval;
}

static int cw2245_erase(struct flash_bank *bank, unsigned int first,
						unsigned int last)
{
	log_info("%s", __func__);
	int retval;
	struct target *target = bank->target;
	struct working_area *write_algorithm = NULL;
	cw2245_load_flash_algo(target, &write_algorithm);

	uint32_t addr = bank->base + bank->sectors[first].offset;
	uint32_t len = bank->sectors[last].offset + bank->sectors[last].size - bank->sectors[first].offset;

	uint32_t args[4] = {0};
	args[0] = 0xBBBBBBBB;
	args[1] = addr;
	args[2] = len;
	retval = target_write_buffer(target, write_algorithm->address + PROGRAM_ARGS_OFFSET, sizeof(args), args);

	log_info("run erase algo , target addr : 0x%08X len : 0x%04X", addr, len);
	int64_t run_algo_start = timeval_ms();
	retval = target_run_algorithm(target,
								  0, NULL,
								  0, NULL,
								  write_algorithm->address,
								  write_algorithm->address + PROGRAM_BKPT_OFFSET,
								  10000, NULL);
	log_info("run erase algo %" PRId64 " ms.[%d sectors]", timeval_ms() - run_algo_start, last - first + 1);
	// uint32_t res[1] = {0};
	// target_read_buffer(target, write_algorithm->address + PROGRAM_ARGS_OFFSET, sizeof(res), res);
	// log_info("++++++++res [%08X]+++++++++.", res[0]);
	// log_info("++++++++res [%08X]+++++++++.", res[1]);
	// log_info("++++++++res [%08X]+++++++++.", res[2]);
	// log_info("++++++++res [%08X]+++++++++.", res[3]);
	if (retval != ERROR_OK)
	{
		LOG_ERROR("Failed to execute algorithm at 0x%" TARGET_PRIxADDR ": %d",
				  write_algorithm->address, retval);
	}

	return retval;
}

static int cw2245_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	// log_info("%s", __func__);
	return ERROR_OK;
}

static int cw2245_load_flash_algo(struct target *target, struct working_area **flash_algorithm)
{
	log_info("%s", __func__);
	static const uint8_t cw2245_flash_write_code[] = {
#include "../../../contrib/loaders/flash/cw2245/cw2245.inc"
	};

	static struct working_area *innner_write_algorithm;
	int retval;

	if (innner_write_algorithm == NULL)
	{
		/* flash write code */
		if (target_alloc_working_area(target, sizeof(cw2245_flash_write_code),
									  &innner_write_algorithm) != ERROR_OK)
		{
			LOG_WARNING("no working area available, can't do block memory writes");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}
	// check ram code
	uint32_t res[4] = {0};
	target_read_buffer(target, innner_write_algorithm->address, sizeof(res), res);

	if(memcmp(res, cw2245_flash_write_code, sizeof(res)))
	{
		int64_t write_algo_start = timeval_ms();
		retval = target_write_buffer(target, innner_write_algorithm->address,
									 sizeof(cw2245_flash_write_code) - 0x100, cw2245_flash_write_code);
		// sub 0x100 is stack
		log_info("load flash algo %" PRId64 " ms[%d bytes].", timeval_ms() - write_algo_start, sizeof(cw2245_flash_write_code));
		if (retval != ERROR_OK)
		{
			target_free_working_area(target, innner_write_algorithm);
			return retval;
		}
	}
	// not free
	// target_free_working_area(target, write_algorithm);
	*flash_algorithm = innner_write_algorithm;
	return retval;
}

static int cw2245_write_block_riscv(struct flash_bank *bank, const uint8_t *buffer,
									uint32_t address, uint32_t words_count)
{
	int64_t write_block_start = timeval_ms();
	// log_info("%s", __func__);
	struct target *target = bank->target;
	uint32_t buffer_size;
	struct working_area *write_algorithm = NULL;
	struct working_area *source;

	cw2245_load_flash_algo(target, &write_algorithm);

	/* memory buffer */
	buffer_size = target_get_working_area_avail(target) & 0xFFFFFF00;
	buffer_size = MIN(words_count * 4, MAX(buffer_size, 256));

	int retval = 0;
	retval = target_alloc_working_area(target, buffer_size, &source);
	/* Allocated size is always word aligned */
	if (retval != ERROR_OK)
	{
		// target_free_working_area(target, write_algorithm);
		LOG_WARNING("no large enough working area available, can't do block memory writes");
		/* target_alloc_working_area() may return ERROR_FAIL if area backup fails:
		 * convert any error to ERROR_TARGET_RESOURCE_NOT_AVAILABLE
		 */
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	while (words_count > 0)
	{
		uint32_t thisrun_words = source->size / 4;

		/* Limit to the amount of data we actually want to write */
		if (thisrun_words > words_count)
			thisrun_words = words_count;

		/* Write data to buffer */
		uint32_t len = thisrun_words * 4;
		int64_t write_data_start = timeval_ms();
		retval = target_write_buffer(target, source->address, len, buffer);
		log_info("load program data %" PRId64 " ms.[0x%X bytes]", timeval_ms() - write_data_start, len);
		if (retval != ERROR_OK)
			break;

		uint32_t args[4] = {0};
		args[0] = 0xAAAAAAAA;
		args[1] = address;
		args[2] = source->address;
		args[3] = len;
		retval = target_write_buffer(target, write_algorithm->address + PROGRAM_ARGS_OFFSET, sizeof(args), args);

		log_info("run program algo addr 0x%08X, src 0x%08X, len 0x%08X", address, source->address, len);
		int64_t run_algo_start = timeval_ms();
		retval = target_run_algorithm(target,
									  0, NULL,
									  0, NULL,
									  write_algorithm->address,
									  write_algorithm->address + PROGRAM_BKPT_OFFSET,
									  10000, NULL);
		log_info("run program algo %" PRId64 " ms.", timeval_ms() - run_algo_start);
		// uint32_t res[1] = {0};
		// target_read_buffer(target, write_algorithm->address + PROGRAM_ARGS_OFFSET, sizeof(res), res);
		// log_info("++++++++res [%08X]+++++++++.", res[0]);

		// uint8_t read_mem[0x2000] = {0};
		// target_read_buffer(target, address, len, read_mem);
		// retval = memcmp(buffer, read_mem, len);
		// log_info("------------- check mem ----------------");
		// log_info("res %d", retval);
		// log_info("------------- check mem ----------------");

		if (retval != ERROR_OK)
		{
			LOG_ERROR("Failed to execute algorithm at 0x%" TARGET_PRIxADDR ": %d",
					  write_algorithm->address, retval);
			break;
		}

		/* Update counters */
		buffer += thisrun_words * 4;
		address += thisrun_words * 4;
		words_count -= thisrun_words;
	}

	target_free_working_area(target, source);

	log_info("write block %" PRId64 " ms.[0x%X bytes]", timeval_ms() - write_block_start, words_count * 4);

	return retval;
}

/** Writes a block to flash either using target algorithm
 *  or use fallback, host controlled halfword-by-halfword access.
 *  Flash controller must be unlocked before this call.
 */
static int cw2245_write_block(struct flash_bank *bank,
							  const uint8_t *buffer, uint32_t address, uint32_t words_count)
{
	struct target *target = bank->target;

	/* The flash write must be aligned to a halfword boundary.
	 * The flash infrastructure ensures it, do just a security check
	 */
	assert(address % 4 == 0);

	int retval;
	retval = cw2245_write_block_riscv(bank, buffer, address, words_count);

	if (retval == ERROR_TARGET_RESOURCE_NOT_AVAILABLE)
	{
		/* if block write failed (no sufficient working area),
		 * we use normal (slow) single halfword accesses */
		LOG_WARNING("couldn't use block writes, falling back to single memory accesses");

		while (words_count > 0)
		{
			retval = target_write_memory(target, address, 4, 1, buffer);
			if (retval != ERROR_OK)
				return retval;

			retval = cw2245_wait_status_busy(bank, 5);
			if (retval != ERROR_OK)
				return retval;

			words_count--;
			buffer += 4;
			address += 4;
		}
	}
	return retval;
}

static int cw2245_write(struct flash_bank *bank, const uint8_t *buffer,
						uint32_t offset, uint32_t count)
{
	// log_info("%s", __func__);
	struct target *target = bank->target;

	if (bank->target->state != TARGET_HALTED)
	{
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* The flash write must be aligned to a word boundary.
	 * The flash infrastructure ensures it, do just a security check
	 */
	assert(offset % 4 == 0);
	assert(count % 4 == 0);

	int retval, retval2;
	uint32_t reg_val;

	reg_val = 1 << REG_EFLASH_CTRL_EFLSH_PORB_POS |
			  0 << REG_EFLASH_CTRL_EFLSH_CEB_POS |
			  0 << REG_EFLASH_CTRL_EFLSH_DPD_POS |
			  0 << REG_EFLASH_CTRL_EFLSH_TMEN_POS |
			  0 << REG_EFLASH_CTRL_EFLSH_RECALL_POS;
	retval = target_write_u32(target, cw2245_get_flash_reg(bank, EFLASH_CTRL), reg_val);
	if (retval != ERROR_OK)
		return retval;

	/* write to flash */
	retval = cw2245_write_block(bank, buffer, bank->base + offset, count / 4);

	return retval;
}

struct cw2245_property_addr
{
	uint32_t device_id;
	uint32_t flash_size;
};

static int cw2245_get_property_addr(struct target *target, struct cw2245_property_addr *addr)
{
	return ERROR_NOT_IMPLEMENTED;
}

static int cw2245_get_device_id(struct flash_bank *bank, uint32_t *device_id)
{
	return ERROR_NOT_IMPLEMENTED;
}

static int cw2245_get_flash_size(struct flash_bank *bank, uint16_t *flash_size_in_kb)
{
	return ERROR_NOT_IMPLEMENTED;
}

static int cw2245_probe(struct flash_bank *bank)
{
	// log_info("%s", __func__);
	struct cw2245_flash_bank *cw2245_info = bank->driver_priv;
	uint16_t flash_size_in_kb = 128;
	uint16_t max_flash_size_in_kb = 128;
	uint32_t block_size = 0x20000;
	uint16_t sector_size = 0x200;
	uint16_t page_size = 32;
	uint32_t base_address = 0x01040000;

	cw2245_info->probed = false;
	cw2245_info->register_base = FLASH_REG_BASE_B0;
	cw2245_info->user_data_offset = 0;
	cw2245_info->option_offset = 0;

	/* default factory read protection level 0 */
	cw2245_info->default_rdp = 0;

	/* set page size, protection granularity and max flash size depending on family */
	cw2245_info->ppage_size = page_size;
	cw2245_info->user_data_offset = 0;
	cw2245_info->option_offset = 0;
	cw2245_info->default_rdp = 0xAA;
	cw2245_info->can_load_options = true;

	LOG_INFO("flash size = %d KiB", flash_size_in_kb);

	/* did we assign flash size? */
	assert(flash_size_in_kb != 0xffff);

	free(bank->sectors);
	bank->sectors = NULL;

	free(bank->prot_blocks);
	bank->prot_blocks = NULL;

	bank->base = base_address;
	bank->size = block_size;

	bank->num_sectors = block_size / sector_size;
	bank->sectors = alloc_block_array(0, sector_size, bank->num_sectors);
	if (!bank->sectors)
		return ERROR_FAIL;

	cw2245_info->probed = true;

	return ERROR_OK;
}

static int cw2245_auto_probe(struct flash_bank *bank)
{
	// log_info("%s", __func__);
	struct cw2245_flash_bank *cw2245_info = bank->driver_priv;
	if (cw2245_info->probed)
		return ERROR_OK;
	return cw2245_probe(bank);
}

#if 0
COMMAND_HANDLER(cw2245_handle_part_id_command)
{
	return ERROR_OK;
}
#endif

static int cw2245_protect_check(struct flash_bank *bank)
{
	// log_info("%s", __func__);
	return ERROR_OK;
}

static int get_cw2245_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	// log_info("%s", __func__);
	const char *device_str;
	const char *rev_str = NULL;

	device_str = "CW2245";
	rev_str = "B";
	command_print_sameline(cmd, "%s - Rev: %s", device_str, rev_str);

	return ERROR_OK;
}

static int cw2245_mass_erase(struct flash_bank *bank)
{
	// log_info("%s", __func__);
	return ERROR_NOT_IMPLEMENTED;
}

COMMAND_HANDLER(cw2245_handle_mass_erase_command)
{
	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	struct target *target = bank->target;
	struct working_area *write_algorithm;
	// retval = stm32x_mass_erase(bank);
	cw2245_load_flash_algo(target, &write_algorithm);
	if (retval == ERROR_OK)
		command_print(CMD, "cw2245 mass erase complete");
	else
		command_print(CMD, "cw2245 mass erase failed");

	return retval;
}

static const struct command_registration cw2245_exec_command_handlers[] = {
	{
		.name = "mass_erase",
		.handler = cw2245_handle_mass_erase_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Erase entire flash device.",
	},
	COMMAND_REGISTRATION_DONE};

static const struct command_registration cw2245_command_handlers[] = {
	{
		.name = "cw2245",
		.mode = COMMAND_ANY,
		.help = "cw2245 flash command group",
		.usage = "",
		.chain = cw2245_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE};

const struct flash_driver cw2245_flash = {
	.name = "cw2245",
	.commands = cw2245_command_handlers,
	.flash_bank_command = cw2245_flash_bank_command,
	.erase = cw2245_erase,
	.protect = cw2245_protect,
	.write = cw2245_write,
	.read = default_flash_read,
	.probe = cw2245_probe,
	.auto_probe = cw2245_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = cw2245_protect_check,
	.info = get_cw2245_info,
	.free_driver_priv = default_flash_free_driver_priv,
};
