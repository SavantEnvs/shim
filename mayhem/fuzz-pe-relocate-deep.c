// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * fuzz-pe-relocate-deep.c - mayhem-owned harness for the PE loader path.
 *
 * Upstream's fuzz-pe-relocate.c stops after read_header(). This one follows
 * handle_image() (pe.c): read_header, the section checks generate_hash()
 * applies to every image, the section layout into an image buffer sized the
 * way the loader sizes it, the .reloc/.sbat lookups, and relocate_coff().
 */

#ifndef SHIM_UNIT_TEST
#define SHIM_UNIT_TEST
#endif
#include "shim.h"

#define MAX_INPUT	(1u << 20)
#define MAX_IMAGE	(1u << 20)

/* what generate_hash() enforces on every image before it is loaded */
static bool
sections_valid(void *data, size_t size, PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	size_t bytes = context->SizeOfHeaders;
	UINTN i;

	if (context->NumberOfSections == 0 || context->FirstSection == NULL)
		return false;

	for (i = 0; i < context->NumberOfSections; i++) {
		EFI_IMAGE_SECTION_HEADER *section = NULL;
		char *base = NULL;
		size_t sz = 0;
		EFI_STATUS status;

		status = get_section_vma(i, data, size, context, &base, &sz, &section);
		if (EFI_ERROR(status))
			return false;
		if (section->SizeOfRawData == 0)
			continue;
		if (section->PointerToRawData > size ||
		    section->SizeOfRawData > size - section->PointerToRawData)
			return false;
		if (section->SizeOfRawData > size - bytes)
			return false;
		bytes += section->SizeOfRawData;
	}
	return true;
}

/* handle_image() only relocates when the .reloc section agrees with the RelocDir */
static bool
reloc_table_matches(uint8_t *image, PE_COFF_LOADER_IMAGE_CONTEXT *context,
		    EFI_IMAGE_SECTION_HEADER *reloc, char *base, size_t sz)
{
	char *table, *table_end;

	table = ImageAddress((char *)image, context->ImageSize,
			     context->RelocDir->VirtualAddress);
	table_end = ImageAddress((char *)image, context->ImageSize,
				 context->RelocDir->VirtualAddress +
				 context->RelocDir->Size - 1);
	return reloc->SizeOfRawData && reloc->Misc.VirtualSize && base &&
	       table == base && table_end && table_end <= base + sz;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	PE_COFF_LOADER_IMAGE_CONTEXT context = { 0, };
	EFI_IMAGE_SECTION_HEADER *section = NULL, *reloc = NULL;
	EFI_STATUS status;
	uint8_t *file, *image;
	size_t alloc_size;
	char *base = NULL;
	size_t sz = 0;
	UINTN i;

	if (size < 1 || size > MAX_INPUT)
		return 0;

	file = malloc(size);
	if (!file)
		return -1;
	memcpy(file, data, size);

	status = read_header(file, size, &context, false);
	if (!EFI_ERROR(status)) {
		PE_COFF_LOADER_IMAGE_CONTEXT other = { 0, };
		(void)read_header(file, size, &other, true);
	}
	if (EFI_ERROR(status) || !sections_valid(file, size, &context))
		goto out;

	if (context.ImageSize > MAX_IMAGE ||
	    context.SectionAlignment > MAX_IMAGE ||
	    context.SizeOfHeaders > size ||
	    context.SizeOfHeaders > context.ImageSize)
		goto out;

	/* same sizing as handle_image() */
	alloc_size = ALIGN_VALUE(context.ImageSize + context.SectionAlignment,
				 PAGE_SIZE);
	image = aligned_alloc(PAGE_SIZE, alloc_size);
	if (!image)
		goto out;
	memset(image, 0, alloc_size);
	memcpy(image, file, context.SizeOfHeaders);

	section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++, section++) {
		char *sbase, *send;
		size_t n;

		if (!(section->Characteristics & EFI_IMAGE_SCN_MEM_READ) ||
		    (section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) ||
		    (section->Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA))
			continue;

		sbase = ImageAddress((char *)image, context.ImageSize,
				     section->VirtualAddress);
		send = ImageAddress((char *)image, context.ImageSize,
				    section->VirtualAddress +
				    section->Misc.VirtualSize - 1);
		if (!sbase || !send || send < sbase ||
		    section->PointerToRawData < context.SizeOfHeaders)
			continue;

		n = section->Misc.VirtualSize;
		if (n > section->SizeOfRawData)
			n = section->SizeOfRawData;
		memcpy(sbase, file + section->PointerToRawData, n);
	}

	(void)get_section_vma_by_name(".sbat", 5, (char *)image, context.ImageSize,
				      &context, &base, &sz, &section);

	if (ImageAddress((char *)image, context.ImageSize, context.EntryPoint) &&
	    !EFI_ERROR(get_section_vma_by_name(".reloc", 6, (char *)image,
					       context.ImageSize, &context,
					       &base, &sz, &reloc)) &&
	    context.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC &&
	    context.RelocDir->Size && reloc_table_matches(image, &context, reloc, base, sz))
		(void)relocate_coff(&context, reloc, file, image);

	free(image);
out:
	free(file);
	return 0;
}

// vim:fenc=utf-8:tw=75:noet
