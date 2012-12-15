#ifndef RENDER_H
#define RENDER_H

#define CAIRO_AVAILABLE 1
#define CAIRO_PDF_AVAILABLE 1

#ifdef HAVE_LIBCAIRO
#ifdef HAVE_CAIRO_CAIRO_H
#include <cairo/cairo.h>
#elif defined HAVE_CAIRO_H
#include <cairo.h>
#else
#undef CAIRO_AVAILABLE
#undef CAIRO_PDF_AVAILABLE
#endif
#ifdef HAVE_CAIRO_CAIRO_PDF_H
#include <cairo/cairo-pdf.h>
#elif defined HAVE_CAIRO_PDF_H
#include <cairo-pdf.h>
#else
#undef CAIRO_PDF_AVAILABLE
#endif
#else
#undef CAIRO_AVAILABLE
#undef CAIRO_PDF_UNAVAILABLE
#endif

#ifndef CAIRO_AVAILABLE
#define cairo_t void			// won't be using cairo
#endif

#endif
