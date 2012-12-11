#ifndef RENDER_H
#define RENDER_H

#ifdef HAVE_LIBCAIRO
#ifdef HAVE_CAIRO_CAIRO_H
#include <cairo/cairo.h>
#elif defined HAVE_CAIRO_H
#include <cairo.h>
#else
#error "cairo rendering requested, but no cairo base headers are available"
#endif
#ifdef HAVE_CAIRO_CAIRO_PDF_H
#include <cairo/cairo-pdf.h>
#elif defined HAVE_CAIRO_PDF_H
#include <cairo-pdf.h>
#else
#error "cairo rendering requested, but no cairo pdf headers are available"
#endif
#else
#define cairo_t void			// won't be using cairo
#endif

#endif
