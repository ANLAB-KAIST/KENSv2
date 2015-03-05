#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kxml.h"


/*
 * FIXME: we do not use it, but you are very welcome to add your 
 * own support code for the character encoding.
 */

#define DEBUG	0

#ifdef DEBUG
#define DBG(x...) do { \
	fprintf (stderr, x); \
} while (0)
#else
#define DBG(x...)
#endif

/**
 * ConvertInput:
 * @in: string in a given encoding
 * @encoding: the encoding used
 *
 * Converts @in into UTF-8 for processing with libxml2 APIs
 *
 * Returns the converted UTF-8 string, or NULL in case of error.
 * Piece of code from http://xmlsoft.org/examples/testWriter.c
 */
xmlChar * ConvertInput(const char *in, const char *encoding)
{
#ifdef HAVE_XML_ENCODING /* FIXME */
	xmlChar *out;
	int ret;
	int size;
	int out_size;
	int temp;
	xmlCharEncodingHandlerPtr handler;

	if (in == 0)
		return 0;

	handler = xmlFindCharEncodingHandler(encoding);

	if (!handler) {
		printf("ConvertInput: no encoding handler found for '%s'\n",
				encoding ? encoding : "");
		return 0;
	}

	size = (int) strlen(in) + 1;
	out_size = size * 2 - 1;
	out = (unsigned char *) xmlMalloc((size_t) out_size);

	if (out != 0) {
		temp = size - 1;
		ret = handler->input(out, &out_size, (const xmlChar *) in, &temp);
		if (ret || temp - size + 1) {
			if (ret) {
				printf("ConvertInput: conversion wasn't successful.\n");
			} else {
				printf
					("ConvertInput: conversion wasn't successful. converted: %i octets.\n",
					 temp);
			}

			xmlFree(out);
			out = 0;
		} else {
			out = (unsigned char *) xmlRealloc(out, out_size + 1);
			out[out_size] = 0;  /*null terminating out */
		}
	} else {
		printf("ConvertInput: no mem\n");
	}

	return out;
#else /* !HAVE_XML_ENCODING */
	return in;
#endif /* HAVE_XML_ENCODING */
}

void ConvertFree (xmlChar *buf)
{
#ifdef HAVE_XML_ENCODING /* FIXME */
	xmlFree (buf);
#endif /* HAVE_XML_ENCODING */
}

