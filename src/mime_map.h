/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Will Glynn <will@willglynn.com>.
 *
 * This source code is under the GNU Public License (GPL) version 3.
 * See COPYING for details.
 *
 */

#ifndef MIME_MAP_H
#define MIME_MAP_H

#include <string>

std::string get_extension_for_mime_type(const std::string& mime_type);

#endif /* MIME_MAP_H */