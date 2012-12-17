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

#include <iomanip>
#include <math.h>

#include "one_page_report.h"

// string constants
const std::string one_page_report::title_version = PACKAGE " " VERSION;
const std::vector<std::string> one_page_report::size_suffixes =
        build_size_suffixes();
// ratio constants
const double one_page_report::page_margin_factor = 0.05;
const double one_page_report::line_space_factor = 0.25;

const one_page_report::config_t one_page_report::default_config = {
    /* filename */ "one_page_report.pdf",
    /* bounds */ plot::bounds_t(0.0, 0.0, 612.0, 792.0), // 8.5x11 inches
    /* header_font_size */ 8.0
};

one_page_report::one_page_report(const config_t &conf_) : 
    conf(conf_), packet_count(0), byte_count(0), earliest(), latest(),
    transport_counts(), bandwidth_histogram(time_histogram::default_config)
{
    earliest = (struct timeval) { 0 };
    latest = (struct timeval) { 0 };

    time_histogram::config_t bh_config = time_histogram::default_config;
    bh_config.graph.title = "TCP Packets Received";
    bh_config.graph.y_tick_font_size = 6.0;
    bh_config.graph.x_tick_font_size = 6.0;
    bh_config.graph.legend_font_size = 5.0;
    bandwidth_histogram = dyn_time_histogram(bh_config);
}

void one_page_report::ingest_packet(const packet_info &pi)
{
    if(earliest.tv_sec == 0) {
        earliest = pi.ts;
    }
    if(pi.ts.tv_sec > latest.tv_sec && pi.ts.tv_usec > latest.tv_usec) {
        latest = pi.ts;
    }

    packet_count++;
    byte_count += pi.caplen;
    transport_counts[pi.family]++;

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
    struct tm start = *localtime(&earliest.tv_sec);
    struct tm stop = *localtime(&latest.tv_sec);
    formatted.str(std::string());
    formatted << "Date range: " <<
        std::setfill('0') << setw(4) << (1900 + start.tm_year) << "-" <<
        std::setw(2) << (1 + start.tm_mon) << "-" <<
        std::setw(2) << start.tm_mday << "T" <<
        std::setw(2) << start.tm_hour << ":" <<
        std::setw(2) << start.tm_min << ":" <<
        std::setw(2) << start.tm_sec <<
        " to " <<
        std::setfill('0') << setw(4) << (1900 + stop.tm_year) << "-" <<
        std::setw(2) << (1 + stop.tm_mon) << "-" <<
        std::setw(2) << stop.tm_mday << "T" <<
        std::setw(2) << stop.tm_hour << ":" <<
        std::setw(2) << stop.tm_min << ":" <<
        std::setw(2) << stop.tm_sec;
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    //// packet count/size
    uint64_t size_log_1000 = (uint64_t) (log(byte_count) / log(1000));
    if(size_log_1000 >= size_suffixes.size()) {
        size_log_1000 = 0;
    }
    formatted.str(std::string());
    formatted << "Packets analyzed: " << packet_count << " (" <<
        std::setprecision(2) << std::fixed <<
        ((double) byte_count) / pow(1000.0, (double) size_log_1000) <<
        " " << size_suffixes.at(size_log_1000) << ")";
    end_of_content = render_text_line(cr, formatted.str(),
            conf.header_font_size, title_line_space, end_of_content, bounds);
    //// protocol breakdown
    uint64_t transport_total = 0;
    for(std::map<uint32_t, uint64_t>::iterator ii = transport_counts.begin();
            ii != transport_counts.end(); ii++) {
        transport_total += ii->second;
    }
    formatted.str(std::string());
    formatted << "Transports: " << "IPv4 " <<
        std::setprecision(2) << std::fixed <<
        ((double) transport_counts[ETHERTYPE_IP] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "IPv6 " <<
        std::setprecision(2) << std::fixed <<
        ((double) transport_counts[ETHERTYPE_IPV6] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "ARP " <<
        std::setprecision(2) << std::fixed <<
        ((double) transport_counts[ETHERTYPE_ARP] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "Other " <<
        std::setprecision(2) << std::fixed <<
        (1.0 - ((double) (transport_counts[ETHERTYPE_ARP] +
            transport_counts[ETHERTYPE_IPV6] +
            transport_counts[ETHERTYPE_ARP]) /
         (double) transport_total)) * 100.0 <<
        "% ";
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

std::vector<std::string> one_page_report::build_size_suffixes()
{
    std::vector<std::string> v;
    v.push_back("B");
    v.push_back("KiB");
    v.push_back("MiB");
    v.push_back("GiB");
    v.push_back("TiB");
    v.push_back("PiB");
    v.push_back("EiB");
    return v;
}
