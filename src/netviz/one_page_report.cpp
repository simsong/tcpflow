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
const double one_page_report::histogram_pad_factor_y = 1.0;
const double one_page_report::address_histogram_width_divisor = 2.5;
// size constants
const double one_page_report::bandwidth_histogram_height = 100.0;
const double one_page_report::address_histogram_height = 100.0;

one_page_report::one_page_report() : 
    source_identifier(), filename("report.pdf"),
    bounds(0.0, 0.0, 611.0, 792.0), header_font_size(8.0),
    top_list_font_size(8.0), histogram_show_top_n_text(3),
    packet_count(0), byte_count(0), earliest(), latest(),
    transport_counts(), bandwidth_histogram(), src_addr_histogram(),
    dst_addr_histogram(), src_port_histogram(), dst_port_histogram(),
    pfall()
{
    earliest = (struct timeval) { 0 };
    latest = (struct timeval) { 0 };

    bandwidth_histogram.parent.title = "TCP Packets Received";
    bandwidth_histogram.parent.pad_left_factor = 0.2;
    bandwidth_histogram.parent.y_tick_font_size = 6.0;
    bandwidth_histogram.parent.x_tick_font_size = 6.0;
    bandwidth_histogram.parent.x_axis_font_size = 8.0;

    pfall.parent.title = "";
    pfall.parent.subtitle = "";
    pfall.parent.x_label = "";
    pfall.parent.y_label = "";
    pfall.parent.pad_left_factor = 0.2;

    dst_addr_histogram.quick_config(address_histogram::DESTINATION, "Top Destination Addresses", "");
    src_addr_histogram.quick_config(address_histogram::SOURCE, "Top Source Addresses", "");
    dst_port_histogram.quick_config(port_histogram::DESTINATION, "Top Destination Ports", "");
    src_port_histogram.quick_config(port_histogram::SOURCE, "Top Source Ports", "");
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
    byte_count += pi.pcap_hdr->caplen;
    transport_counts[pi.ether_type()]++; // should we handle VLANs?

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
    std::string fname = outdir + "/" + filename;

    surface = cairo_pdf_surface_create(fname.c_str(),
				 bounds.width,
				 bounds.height);
    cr = cairo_create(surface);

    double pad_size = bounds.width * page_margin_factor;
    plot::bounds_t pad_bounds(bounds.x + pad_size,
            bounds.y + pad_size, bounds.width - pad_size * 2,
            bounds.height - pad_size * 2);
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
    double title_line_space = report.header_font_size * line_space_factor;
    //// version
    render_text_line(title_version, report.header_font_size,
            title_line_space);
    //// input
    formatted.str(std::string());
    formatted << "Input: " << report.source_identifier;
    render_text_line(formatted.str(), report.header_font_size,
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
    render_text_line(formatted.str(), report.header_font_size,
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
    render_text_line(formatted.str(), report.header_font_size,
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
    render_text_line(formatted.str(), report.header_font_size,
            title_line_space);
    //// protocol breakdown
    uint64_t transport_total = 0;
    for(std::map<uint32_t, uint64_t>::const_iterator ii =
                report.transport_counts.begin();
            ii != report.transport_counts.end(); ii++) {
        transport_total += ii->second;
    }
  
    // SLG - Although this is the C++ way to do formatting
    // code is much simpler to view if you use sprintf(). That's what
    // most people do.

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
    render_text_line(formatted.str(), report.header_font_size,
            title_line_space);
    // trailing pad for entire header
    end_of_content += title_line_space * 4;
#endif
}

void one_page_report::render_pass::render_text(std::string text,
        double font_size, double x_offset,
        cairo_text_extents_t &rendered_extents)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_set_font_size(surface, font_size);
    cairo_set_source_rgb(surface, 0.0, 0.0, 0.0);
    cairo_text_extents(surface, text.c_str(), &rendered_extents);
    cairo_move_to(surface, x_offset, end_of_content + rendered_extents.height);
    cairo_show_text(surface, text.c_str());
#endif
}

void one_page_report::render_pass::render_text_line(std::string text,
        double font_size, double line_space)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_text_extents_t extents;
    render_text(text, font_size, 0.0, extents);
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
    // histograms
    double width = surface_bounds.width / address_histogram_width_divisor;

    plot::bounds_t left_bounds(0.0, end_of_content, width,
            address_histogram_height);
    report.src_addr_histogram.render(surface, left_bounds);

    plot::bounds_t right_bounds(surface_bounds.width - width, end_of_content,
            width, address_histogram_height);
    report.dst_addr_histogram.render(surface, right_bounds);

    end_of_content += max(left_bounds.height, right_bounds.height);

    // text stats
    vector<count_histogram::count_pair> left_list =
        report.src_addr_histogram.parent_count_histogram.get_top_list();
    vector<count_histogram::count_pair> right_list =
        report.dst_addr_histogram.parent_count_histogram.get_top_list();

    render_dual_histograms_top_n(left_list, right_list, left_bounds, right_bounds);
#endif
}

void one_page_report::render_pass::render_port_histograms()
{
#ifdef CAIRO_PDF_AVAILABLE
    double width = surface_bounds.width / address_histogram_width_divisor;

    plot::bounds_t left_bounds(0.0, end_of_content, width,
            address_histogram_height);
    report.src_port_histogram.render(surface, left_bounds);

    plot::bounds_t right_bounds(surface_bounds.width - width, end_of_content,
            width, address_histogram_height);
    report.dst_port_histogram.render(surface, right_bounds);

    end_of_content += max(left_bounds.height, right_bounds.height);

    // text stats
    vector<count_histogram::count_pair> left_list =
        report.src_port_histogram.parent_count_histogram.get_top_list();
    vector<count_histogram::count_pair> right_list =
        report.dst_port_histogram.parent_count_histogram.get_top_list();

    render_dual_histograms_top_n(left_list, right_list, left_bounds, right_bounds);
#endif
}

void one_page_report::render_pass::render_dual_histograms_top_n(
        const vector<count_histogram::count_pair> &left_list,
        const vector<count_histogram::count_pair> &right_list,
        const plot::bounds_t &left_hist_bounds,
        const plot::bounds_t &right_hist_bounds)
{
#ifdef CAIRO_PDF_AVAILABLE
    for(size_t ii = 0; ii < report.histogram_show_top_n_text; ii++) {
        cairo_text_extents_t left_extents, right_extents;
        if(left_list.size() > ii) {
            stringstream ss;
            count_histogram::count_pair pair = left_list.at(ii);
            ss << ii + 1 << ". " << pair.first << " - " << pair.second <<
                " (" << "%)";
            render_text(ss.str(), report.top_list_font_size, left_hist_bounds.x,
                    left_extents);
        }
        if(right_list.size() > ii) {
            stringstream ss;
            count_histogram::count_pair pair = right_list.at(ii);
            ss << ii + 1 << ". " << pair.first << " - " << pair.second <<
                " (" << "%)";
            render_text(ss.str(), report.top_list_font_size, right_hist_bounds.x,
                    left_extents);
        }
        end_of_content += max(left_extents.height, right_extents.height) * 1.5;
    }

    end_of_content += max(left_hist_bounds.height, right_hist_bounds.height) *
        (histogram_pad_factor_y - 1.0);
#endif
}

/* SLG - Should the prefixes be in a structure where the structure encodes both the
   prefix and its multiplier? It seems that the position encodes the multiplier here,
   but I would like to see that explicit. ALso the prefixes are "", "K", "M", etc,
   the B is really not a prefix...
*/
   
   
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
