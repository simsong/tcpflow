/**
 * one_page_report.cpp: 
 * Generate a one-page visualization from TCP packets
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"
#include "render.h"

#include "one_page_report.h"

// string constants
static const std::string title_version = PACKAGE " " VERSION;
// ratio constants
static const double page_margin_factor = 0.05;
static const double line_space_factor = 0.25;

const one_page_report::config_t one_page_report::default_config = {
    /* filename */ "one_page_report.pdf",
    /* bounds */ plot::bounds_t(0.0, 0.0, 612.0, 792.0), // 8.5x11 inches
    /* header_font_size */ 8.0
};

one_page_report::one_page_report(const config_t &conf_) : 
    conf(conf_), packet_count(0), byte_count(0),
    bandwidth_histogram(time_histogram::default_config)
{
    time_histogram::config_t bh_config = time_histogram::default_config;
    bh_config.graph.title = "TCP Packets Received";
    bh_config.graph.y_tick_font_size = 6.0;
    bh_config.graph.x_tick_font_size = 6.0;
    bh_config.graph.legend_font_size = 5.0;
    bandwidth_histogram = dyn_time_histogram(bh_config);
}

void one_page_report::ingest_packet(const packet_info &pi)
{
    packet_count++;
    byte_count += pi.caplen;
    bandwidth_histogram.ingest_packet(pi);
}

void one_page_report::render(const std::string &outdir)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_t *cr;
    cairo_surface_t *surface;
    std::string fname = outdir + "/" + conf.filename;

    surface = cairo_pdf_surface_create(fname.c_str(),
				 conf.bounds.width,
				 conf.bounds.height);
    cr = cairo_create(surface);

    double pad_size = conf.bounds.width * page_margin_factor;
    plot::bounds_t pad_bounds(conf.bounds.x + pad_size,
            conf.bounds.y + pad_size, conf.bounds.width - pad_size * 2,
            conf.bounds.height - pad_size * 2);
    cairo_translate(cr, pad_bounds.x, pad_bounds.y);

    double end_of_content = 0.0; // x value of the lowest point rendered so far

    end_of_content = render_header(cr, end_of_content, pad_bounds);
    end_of_content = render_bandwidth_histogram(cr, end_of_content, pad_bounds);

    // cleanup
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
#endif
}

double one_page_report::render_header(cairo_t *cr, double end_of_content,
        const plot::bounds_t &bounds)
{
    std::stringstream formatted;
    // title
    double title_line_space = conf.header_font_size * line_space_factor;
    //// version
    end_of_content = render_text_line(cr, title_version, conf.header_font_size,
            title_line_space, end_of_content, bounds);
    //// input
    formatted.str(std::string());
    formatted << "Input: " << "some_such.pcap";
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    //// trailing pad
    end_of_content += title_line_space * 4;
    // quick stats
    //// date range
    formatted.str(std::string());
    formatted << "Date range: " << "2012-12-14T15:24:58-0500" << " to " <<
        "2012-12-14T15:26:17-0500";
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    //// packet count/size
    formatted.str(std::string());
    formatted << "Packets analyzed: " << packet_count << " (" << byte_count <<
        " " << "B" << ")";
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    //// protocol breakdown
    formatted.str(std::string());
    formatted << "Protocols: " << "IPv4 " << "99" << "% " << "IPv6 " << "0" <<
        "% " << "ARP " << "0" << "% " << "Other " << "0" << "% ";
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    // trailing pad for entire header
    end_of_content += title_line_space * 8;

    return end_of_content;
}

double one_page_report::render_text_line(cairo_t *cr, std::string text,
        double font_size, double line_space, double end_of_content,
        const plot::bounds_t &parent_bounds)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_set_font_size(cr, font_size);
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_text_extents_t extents;
    cairo_text_extents(cr, text.c_str(), &extents);
    cairo_move_to(cr, 0.0, end_of_content + extents.height);
    cairo_show_text(cr, text.c_str());
    return end_of_content + extents.height + line_space;
#else
    return end_of_content;
#endif
}

double one_page_report::render_bandwidth_histogram(cairo_t *cr,
        double end_of_content, const plot::bounds_t &parent_bounds)
{
#ifdef CAIRO_PDF_AVAILABLE
    plot::bounds_t bounds(0.0, end_of_content, parent_bounds.width, 100.0);

    bandwidth_histogram.render(cr, bounds);

    return end_of_content + bounds.height;
#else
    return end_of_content;
#endif
}
