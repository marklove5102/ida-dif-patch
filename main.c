#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "grepline.h"

struct memory_region {
	size_t size;
	char * data;
};

struct single_patch_instruction {
	unsigned long long offset;
	char old;
	char new;
};

struct all_patch_instructions {
	size_t amount;
	char has_64bit_offsets;
	char * input_binary;
	struct single_patch_instruction ** instruction;
};

/* This is only needed on MSVC 2013 afaict. */
#ifdef _WIN32
#	ifndef _CRT_SECURE_NO_WARNINGS
#		define _CRT_SECURE_NO_WARNINGS
#	endif /*_CRT_SECURE_NO_WARNINGS*/
#endif /*_WIN32*/

static void help(const char * exe) {
	printf("IDA .dif patcher\nUsage: %s .dif output\n\t.dif - path to a .dif file to use\n\toutput - output file\n", exe);
}

static char check_ida_dif_header(FILE * ida_dif_file) {
	static char * known_first_line[3] = {
		"This difference file is created by The Interactive Disassembler", /* IDA 5.x Free says this */
		"This difference file has been created by IDA Pro", /* IDA 6.x Pro says this */
		"This difference file was created by IDA" /* IDA 9.2 Free says this */
	};
	static size_t known_length[3] = {
		63,
		48,
		39
	};
	static size_t limit = 3;

	size_t result = 0;
	size_t len = 0;
	char * line = NULL;
	size_t counter = 0;

	grepline(&line, &len, ida_dif_file);
	while(counter < limit) {
		result += !!memcmp(line, known_first_line[counter], known_length[counter]);
		++counter;
	}
	free(line);
/* The result will be equal to limit only if nothing was found. So if the
 * comparison is true, the result is bad. */
	result = result == limit;
	return (char)result;
}

static char check_if_next_line_is_empty(FILE * ida_dif_file) {
	char result;
	size_t len = 0;
	char * line = NULL;
	grepline(&line, &len, ida_dif_file);
	free(line);
	result = len == 1;
	return result;
}

static char * get_input_file(FILE * ida_dif_file) {
	size_t len = 0;
	char * result = NULL;
	char * line = NULL;
	grepline(&line, &len, ida_dif_file);
	if(line == NULL) {
		fputs("ERROR: could not allocate memory for grepline in get_input_file\n", stderr);
		return result;
	}
	result = malloc(len);
	if(result == NULL) {
		free(line);
		fputs("ERROR: could not allocate memory for result in get_input_file\n", stderr);
		return result;
	}
	memcpy(result, line, len);
	result[len-1] = '\0';
	free(line);
	return result;
}

static char check_if_instruction_line_has_correct_length(const size_t len) {
/* This array would contain 15 (32bit) and 23 (64bit), but because of how
 * grepline and GNU getline work, we need to account for the newline.
 * And if that's not bad enough, we need to take account of CRLF. */
	static size_t known_length_with_instruction[4] = {16, 17, 24, 25};
	static size_t limit = 4;
	size_t counter = 0;
	char result = 0;

	while(counter < limit) result |= (len == known_length_with_instruction[counter++]);
	return result;
}

static struct all_patch_instructions * parse_instructions_from_dif_file(FILE * ida_dif_file) {
	char offset[17] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	char old[3] = {0, 0, 0};
	char new[3] = {0, 0, 0};

	size_t counter = 0;
	size_t len = 0;
	char * line = NULL;
	char is_64bit;

	struct all_patch_instructions * result = malloc(sizeof(struct all_patch_instructions));
	if(result == NULL) {
		return NULL;
	}

	result->input_binary = get_input_file(ida_dif_file);
	if(result->input_binary == NULL) {
		free(result);
		return NULL;
	}
	result->amount = 0;
	result->has_64bit_offsets = 0;

	while(!feof(ida_dif_file)) {
		grepline(&line, &len, ida_dif_file);
		if(check_if_instruction_line_has_correct_length(len)) {
			counter = result->amount;
			result->amount += 1;
			result->instruction = realloc(result->instruction, sizeof(void*) * result->amount);
			is_64bit = line[16] == ':';
			result->instruction[counter] = malloc(sizeof(struct single_patch_instruction));

			memcpy(offset, line, 8 << is_64bit);
			result->instruction[counter]->offset = strtoll(offset, NULL, 16);
			memset(offset, 0, 8 << is_64bit);
			result->has_64bit_offsets |= ((result->instruction[counter]->offset > 0x00000000FFFFFFFF) && is_64bit);

			memcpy(old, line + 10 + (is_64bit << 3), 2);
			result->instruction[counter]->old = strtol(old, NULL, 16);

			memcpy(new, line + 13 + (is_64bit << 3), 2);
			result->instruction[counter]->new = strtol(new, NULL, 16);
		}
	}
	if(line != NULL) {
		free(line);
		line = NULL;
	}
	puts("OK: finished parsing dif file");
	return result;
}

static void free_instruction(struct all_patch_instructions * x) {
	size_t counter = 0;
	while(counter < x->amount) {
		free(x->instruction[counter]);
		x->instruction[counter++] = NULL;
	}
	free(x->instruction);
	x->instruction = NULL;
	free(x->input_binary);
	x->input_binary = NULL;
	free(x);
}

static char sanity_check_ida_dif_file(FILE * ida_dif_file) {
	char ida_version_looks_bad;
	char second_line_is_empty;

	if(ida_dif_file == NULL) {
		fputs("ERROR: failed to open dif file.\n", stderr);
		return 1;
	}

	ida_version_looks_bad = check_ida_dif_header(ida_dif_file);
	if(ida_version_looks_bad) {
		fputs("ERROR: unsupported disassembler detected.\n", stderr);
		fclose(ida_dif_file);
		return 1;
	}
	else puts("OK: one of known IDA versions detected.");

	second_line_is_empty = check_if_next_line_is_empty(ida_dif_file);
	if(!second_line_is_empty) {
		fputs("ERROR: second line is not empty.\n", stderr);
		fclose(ida_dif_file);
		return 1;
	} else puts("OK: second line is empty.");

	return 0;
}

static struct memory_region * eat_file(const char * path) {
	struct memory_region * result;
	size_t file_size;
	FILE * input_file = fopen(path, "rb");

	fseek(input_file, 0, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);
	result = malloc(sizeof(struct memory_region));
	if(result == NULL) {
		fclose(input_file);
		fputs("ERROR: could not allocate memory for the memory region structure\n", stderr);
		return result;
	}
	result->size = file_size;
	result->data = malloc(file_size);
	if(result->data == NULL) {
		free(result);
		result = NULL;
		fclose(input_file);
		fputs("ERROR: could not allocate memory for the whole file\n", stderr);
		return result;
	}
	fread(result->data, result->size, 1, input_file);
	fclose(input_file);
	printf("OK: successfully ate file %s of size %zu\n", path, result->size);
	return result;
}

static size_t apply_instructions_to_image(struct all_patch_instructions * parsed_dif_file, struct memory_region * image) {
	size_t counter = 0;
	size_t result = 0;
	unsigned long long offset;
	char new;
	char old;

	while(counter < parsed_dif_file->amount) {
		offset = parsed_dif_file->instruction[counter]->offset;
		old = parsed_dif_file->instruction[counter]->old;
		new = parsed_dif_file->instruction[counter]->new;
		result += (old != image->data[offset]);
		if(image->size >= offset) {
			image->data[offset] = new;
		} else {
			return (size_t)-1;
		}
		++counter;
	}
	return result;
}

static void free_memory_region(struct memory_region * x) {
	free(x->data);
	x->data = NULL;
	free(x);
}

int main(int argc, char ** argv) {
	struct all_patch_instructions * parsed_dif_file;
	struct memory_region * original_content;
	size_t how_did_it_go;
	FILE * ida_dif_file;
	FILE * destination_binary;

	const char system_is_less_than_64bit = !(sizeof(size_t) >> 3);

	if(argc != 3) {
		help(argv[0]);
		return 1;
	}

	ida_dif_file = fopen(argv[1], "r");
	if(sanity_check_ida_dif_file(ida_dif_file)) {
		fclose(ida_dif_file);
		return 1;
	}

	parsed_dif_file = parse_instructions_from_dif_file(ida_dif_file);
	fclose(ida_dif_file);
	if(system_is_less_than_64bit && parsed_dif_file->has_64bit_offsets) {
		free_instruction(parsed_dif_file);
		parsed_dif_file = NULL;
		fputs("ERROR: IDP does not support patching big files yet (e.g. 64 bit offsets on 32 bit computers) (I kinda don't want to implement it, working on the memory image is 100x easier to implement)\n", stderr);
		return 1;
	}

	original_content = eat_file(parsed_dif_file->input_binary);
	if(original_content == NULL) {
		free_instruction(parsed_dif_file);
		parsed_dif_file = NULL;
		return 1;
	}

	how_did_it_go = apply_instructions_to_image(parsed_dif_file, original_content);
	free_instruction(parsed_dif_file);
	parsed_dif_file = NULL;
	if(how_did_it_go == (size_t)-1) {
		free_memory_region(original_content);
		puts("ERROR: offsets are greater than file size");
		return 1;
	} else if(how_did_it_go) {
		free_memory_region(original_content);
		puts("ERROR: old values did not match the ones found in the file");
		return 1;
	}

	destination_binary = fopen(argv[2], "wb");
	if(destination_binary == NULL) {
		free_memory_region(original_content);
		fprintf(stderr, "ERROR: could not open output file %s\n", argv[2]);
		return 1;
	}

	fwrite(original_content->data, original_content->size, 1, destination_binary);
	free_memory_region(original_content);
	fclose(destination_binary);
	puts("OK: success!");

	return 0;
}
