#ifndef UNICODE_ESCAPE_H
#define UNICODE_ESCAPE_H

#include <string>

/** \addtogroup bulk_extractor_APIs
 * @{
 */
/** \file */
std::string validateOrEscapeUTF8(const std::string &input, bool escape_bad_UTF8,bool escape_backslash);

#endif
