#ifndef _KXML_H_
#define _KXML_H_

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>

#define KXML_ENCODING "EUC-KR"

extern xmlChar * ConvertInput(const char *in, const char *encoding);
extern void ConvertFree (xmlChar *buf);

#endif /* _KXML_H_ */

