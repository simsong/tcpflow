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

#include <ctime>
#include <iomanip>
#include <math.h>

#include "one_page_report.h"

// string constants
const std::string one_page_report::title_version = PACKAGE " " VERSION;
const std::vector<std::string> one_page_report::size_suffixes =
        one_page_report::build_size_suffixes();
// ratio constants
const double one_page_report::page_margin_factor = 0.05;
const double one_page_report::line_space_factor = 0.25;
const double one_page_report::histogram_pad_factor_y = 1.2;
const double one_page_report::address_histogram_width_divisor = 2.5;
// size constants
const double one_page_report::bandwidth_histogram_height = 100.0;
const double one_page_report::address_histogram_height = 150.0;

const one_page_report::config_t one_page_report::default_config = {
    /* filename */ "one_page_report.pdf",
    /* bounds */ plot::bounds_t(0.0, 0.0, 612.0, 792.0), // 8.5x11 inches
    /* header_font_size */ 8.0
};

one_page_report::one_page_report(const config_t &conf_) : 
    source_identifier(),
    conf(conf_), packet_count(0), byte_count(0), earliest(), latest(),
    transport_counts(), bandwidth_histogram(time_histogram::default_config),
    src_addr_histogram(address_histogram::default_config),
    dst_addr_histogram(address_histogram::default_config),
    src_port_histogram(port_histogram::default_config),
    dst_port_histogram(port_histogram::default_config),
    pfall(packetfall::default_config)
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
    src_addr_histogram.ingest_packet(pi);
    dst_addr_histogram.ingest_packet(pi);
    src_port_histogram.ingest_packet(pi);
    dst_port_histogram.ingest_packet(pi);
    pfall.ingest_packet(pi);
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

    render_pass pass(*this, cr, pad_bounds);

    pass.render_header();
    pass.render_bandwidth_histogram();
    pass.render_map();
    pass.render_packetfall();
    pass.render_address_histograms();
    pass.render_port_histograms();

    // cleanup
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
#endif
}

void one_page_report::render_pass::render_header()
{
#ifdef CAIRO_PDF_AVAILABLE
    std::stringstream formatted;
    // title
    double title_line_space = report.conf.header_font_size * line_space_factor;
    //// version
    render_text_line(title_version, report.conf.header_font_size,
            title_line_space);
    //// input
    formatted.str(std::string());
    formatted << "Input: " << report.source_identifier;
    render_text_line(formatted.str(), report.conf.header_font_size,
            title_line_space);
    //// date generated
    time_t gen_unix = time(0);
    struct tm gen_time = *localtime(&gen_unix);
    formatted.str(std::string());
    formatted << "Generated: " << 
        std::setfill('0') << setw(4) << (1900 + gen_time.tm_year) << "-" <<
        std::setw(2) << (1 + gen_time.tm_mon) << "-" <<
        std::setw(2) << gen_time.tm_mday << "T" <<
        std::setw(2) << gen_time.tm_hour << ":" <<
        std::setw(2) << gen_time.tm_min << ":" <<
        std::setw(2) << gen_time.tm_sec;
    render_text_line(formatted.str(), report.conf.header_font_size,
            title_line_space);
    //// trailing pad
    end_of_content += title_line_space * 4;
    // quick stats
    //// date range
    struct tm start = *localtime(&report.earliest.tv_sec);
    struct tm stop = *localtime(&report.latest.tv_sec);
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
    render_text_line(formatted.str(), report.conf.header_font_size,
            title_line_space);
    //// packet count/size
    uint64_t size_log_1000 = (uint64_t) (log(report.byte_count) / log(1000));
    if(size_log_1000 >= size_suffixes.size()) {
        size_log_1000 = 0;
    }
    formatted.str(std::string());
    formatted << "Packets analyzed: " << report.packet_count << " (" <<
        std::setprecision(2) << std::fixed <<
        ((double) report.byte_count) / pow(1000.0, (double) size_log_1000) <<
        " " << size_suffixes.at(size_log_1000) << ")";
    render_text_line(formatted.str(), report.conf.header_font_size,
            title_line_space);
    //// protocol breakdown
    uint64_t transport_total = 0;
    for(std::map<uint32_t, uint64_t>::const_iterator ii =
                report.transport_counts.begin();
            ii != report.transport_counts.end(); ii++) {
        transport_total += ii->second;
    }
    formatted.str(std::string());
    formatted << "Transports: " << "IPv4 " <<
        std::setprecision(2) << std::fixed <<
        ((double) report.transport_counts[ETHERTYPE_IP] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "IPv6 " <<
        std::setprecision(2) << std::fixed <<
        ((double) report.transport_counts[ETHERTYPE_IPV6] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "ARP " <<
        std::setprecision(2) << std::fixed <<
        ((double) report.transport_counts[ETHERTYPE_ARP] /
         (double) transport_total) * 100.0 <<
        "% " <<
        "Other " <<
        std::setprecision(2) << std::fixed <<
        (1.0 - ((double) (report.transport_counts[ETHERTYPE_IP] +
            report.transport_counts[ETHERTYPE_IPV6] +
            report.transport_counts[ETHERTYPE_ARP]) /
         (double) transport_total)) * 100.0 <<
        "% ";
    render_text_line(formatted.str(), report.conf.header_font_size,
            title_line_space);
    // trailing pad for entire header
    end_of_content += title_line_space * 8;
#endif
}

void one_page_report::render_pass::render_text_line(std::string text,
        double font_size, double line_space)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_set_font_size(surface, font_size);
    cairo_set_source_rgb(surface, 0.0, 0.0, 0.0);
    cairo_text_extents_t extents;
    cairo_text_extents(surface, text.c_str(), &extents);
    cairo_move_to(surface, 0.0, end_of_content + extents.height);
    cairo_show_text(surface, text.c_str());
    end_of_content += extents.height + line_space;
#endif
}

void one_page_report::render_pass::render_bandwidth_histogram()
{
#ifdef CAIRO_PDF_AVAILABLE
    plot::bounds_t bounds(0.0, end_of_content, surface_bounds.width,
            bandwidth_histogram_height);

    report.bandwidth_histogram.render(surface, bounds);

    end_of_content += bounds.height * histogram_pad_factor_y;
#endif
}

void one_page_report::render_pass::render_packetfall()
{
#ifdef CAIRO_PDF_AVAILABLE
    plot::bounds_t bounds(0.0, end_of_content, surface_bounds.width,
            bandwidth_histogram_height);

    report.pfall.render(surface, bounds);

    end_of_content += bounds.height * histogram_pad_factor_y;
#endif
}

void one_page_report::render_pass::render_map()
{
#ifdef CAIRO_PDF_AVAILABLE
#endif
}

void one_page_report::render_pass::render_address_histograms()
{
#ifdef CAIRO_PDF_AVAILABLE
    double width = surface_bounds.width / address_histogram_width_divisor;

    plot::bounds_t bounds(0.0, end_of_content, width, address_histogram_height);
    report.src_addr_histogram.render(surface, bounds);

    bounds = plot::bounds_t(surface_bounds.width - width, end_of_content,
            width, address_histogram_height);
    report.dst_addr_histogram.render(surface, bounds);

    end_of_content += bounds.height * histogram_pad_factor_y;
#endif
}

void one_page_report::render_pass::render_port_histograms()
{
#ifdef CAIRO_PDF_AVAILABLE
    double width = surface_bounds.width / address_histogram_width_divisor;

    plot::bounds_t bounds(0.0, end_of_content, width, address_histogram_height);
    report.src_port_histogram.render(surface, bounds);

    bounds = plot::bounds_t(surface_bounds.width - width, end_of_content,
            width, address_histogram_height);
    report.dst_port_histogram.render(surface, bounds);

    end_of_content += bounds.height * histogram_pad_factor_y;
#endif
}

std::vector<std::string> one_page_report::build_size_suffixes()
{
    std::vector<std::string> v;
    v.push_back("B");
    v.push_back("KB");
    v.push_back("MB");
    v.push_back("GB");
    v.push_back("TB");
    v.push_back("PB");
    v.push_back("EB");
    return v;
}
