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

#include "be13_api/utils.h"
#include "plot_view.h"
#ifdef HAVE_LIBCAIRO
#include "tcpflow.h"
#include "tcpip.h"

#include <ctime>
#include <iomanip>
#include <math.h>

#include "one_page_report.h"

using namespace std;

const unsigned int one_page_report::max_bars = 100;
const unsigned int one_page_report::port_colors_count = 4;
// string constants
const string one_page_report::title_version = PACKAGE_NAME " " PACKAGE_VERSION;
const string one_page_report::generic_legend_format = "Port %d";
const vector<one_page_report::transport_type> one_page_report::display_transports =
        one_page_report::build_display_transports();
// ratio constants
const double one_page_report::page_margin_factor = 0.05;
const double one_page_report::line_space_factor = 0.25;
const double one_page_report::histogram_pad_factor_y = 1.1;
const double one_page_report::address_histogram_width_divisor = 2.2;
// size constants
const double one_page_report::packet_histogram_height = 100.0;
const double one_page_report::address_histogram_height = 125.0;
const double one_page_report::port_histogram_height = 100.0;
const double one_page_report::legend_height = 16.0;
// color constants
const plot_view::rgb_t one_page_report::default_color(0.67, 0.67, 0.67);
const plot_view::rgb_t one_page_report::color_orange(1.00, 0.47, 0.00);
const plot_view::rgb_t one_page_report::color_red(1.00, 0.00, 0.00);
const plot_view::rgb_t one_page_report::color_magenta(0.75, 0.00, 0.60);
const plot_view::rgb_t one_page_report::color_purple(0.58, 0.00, 0.75);
const plot_view::rgb_t one_page_report::color_deep_purple(0.40, 0.00, 0.75);
const plot_view::rgb_t one_page_report::color_blue(0.02, 0.00, 1.00);
const plot_view::rgb_t one_page_report::color_teal(0.00, 0.75, 0.65);
const plot_view::rgb_t one_page_report::color_green(0.02, 0.75, 0.00);
const plot_view::rgb_t one_page_report::color_yellow(0.99, 1.00, 0.00);
const plot_view::rgb_t one_page_report::color_light_orange(1.00, 0.73, 0.00);
const plot_view::rgb_t one_page_report::cdf_color(0.00, 0.00, 0.00);

one_page_report::one_page_report(int max_histogram_size) : 
    source_identifier(), filename("report.pdf"),
    bounds(0.0, 0.0, 611.0, 792.0), header_font_size(8.0),
    top_list_font_size(8.0), histogram_show_top_n_text(3),
    packet_count(0), byte_count(0), earliest(), latest(), transport_counts(),
    ports_in_time_histogram(), color_labels(), packet_histogram(),
    src_port_histogram(), dst_port_histogram(), pfall(), netmap(),
    src_tree(max_histogram_size), dst_tree(max_histogram_size), port_aliases(),
    port_colormap()
{
    earliest = (struct timeval) { 0 };
    latest = (struct timeval) { 0 };

    port_colormap[PORT_HTTP] = color_blue;
    port_colormap[PORT_HTTP_ALT_0] = color_blue;
    port_colormap[PORT_HTTP_ALT_1] = color_blue;
    port_colormap[PORT_HTTP_ALT_2] = color_blue;
    port_colormap[PORT_HTTP_ALT_3] = color_blue;
    port_colormap[PORT_HTTP_ALT_4] = color_blue;
    port_colormap[PORT_HTTP_ALT_5] = color_blue;
    port_colormap[PORT_HTTPS] = color_green;
    port_colormap[PORT_SSH] = color_purple;
    port_colormap[PORT_FTP_CONTROL] = color_red;
    port_colormap[PORT_FTP_DATA] = color_red;

    // build null alias map to avoid requiring special handling for unmapped ports
    for(int ii = 0; ii <= 65535; ii++) {
        port_aliases[ii] = ii;
    }
}

void one_page_report::ingest_packet(const be13::packet_info &pi)
{
    if(earliest.tv_sec == 0 || (pi.ts.tv_sec < earliest.tv_sec ||
                (pi.ts.tv_sec == earliest.tv_sec && pi.ts.tv_usec < earliest.tv_usec))) {
        earliest = pi.ts;
    }
    if(pi.ts.tv_sec > latest.tv_sec || (pi.ts.tv_sec == latest.tv_sec && pi.ts.tv_usec > latest.tv_usec)) {
        latest = pi.ts;
    }

    size_t packet_length = pi.pcap_hdr->len;
    packet_count++;
    byte_count += packet_length;
    transport_counts[pi.ether_type()] += packet_length; // should we handle VLANs?

    // break out TCP/IP info and feed child views

    // feed IP-only views
    uint8_t ip_ver = 0;
    if(pi.is_ip4()) {
        ip_ver = 4;

        src_tree.add((uint8_t *) pi.ip_data + pi.ip4_src_off, IP4_ADDR_LEN, packet_length);
        dst_tree.add((uint8_t *) pi.ip_data + pi.ip4_dst_off, IP4_ADDR_LEN, packet_length);
    }
    else if(pi.is_ip6()) {
        ip_ver = 6;

        src_tree.add((uint8_t *) pi.ip_data + pi.ip6_src_off, IP6_ADDR_LEN, packet_length);
        dst_tree.add((uint8_t *) pi.ip_data + pi.ip6_dst_off, IP6_ADDR_LEN, packet_length);
    }
    else {
        packet_histogram.insert(pi.ts, 0, packet_length, time_histogram::F_NON_TCP);
        return;
    }


    // feed TCP views
    uint16_t tcp_src = 0, tcp_dst = 0;
    bool has_tcp = false;

    switch(ip_ver) {
        case 4:
            if(!pi.is_ip4_tcp()) {
                break;
            }
            tcp_src = pi.get_ip4_tcp_sport();
            tcp_dst = pi.get_ip4_tcp_dport();
            has_tcp = true;
            break;
        case 6:
            if(!pi.is_ip6_tcp()) {
                break;
            }
            tcp_src = pi.get_ip6_tcp_sport();
            tcp_dst = pi.get_ip6_tcp_dport();
            has_tcp = true;
            break;
        default:
            return;
    }

    if(!has_tcp) {
        packet_histogram.insert(pi.ts, 0, packet_length, time_histogram::F_NON_TCP);
        return;
    }

    // if either the TCP source or destination is a pre-colored port, submit that
    // port to the time histogram
    port_colormap_t::const_iterator tcp_src_color = port_colormap.find(tcp_src);
    port_colormap_t::const_iterator tcp_dst_color = port_colormap.find(tcp_dst);
    in_port_t packet_histogram_port = tcp_src;
    // if dst is colored and src isn't; use dst instead
    if(tcp_dst_color != port_colormap.end() && tcp_src_color == port_colormap.end()) {
        packet_histogram_port = tcp_dst;
    }
    // if both are colored, alternate src and dst
    else if(tcp_src_color != port_colormap.end() && tcp_dst_color != port_colormap.end() &&
            packet_count % 2 == 0) {
        packet_histogram_port = tcp_dst;
    }
    // record that this port appears in the histogram for legend building purposes
    ports_in_time_histogram[packet_histogram_port] = true;
    packet_histogram.insert(pi.ts, packet_histogram_port, packet_length);

    src_port_histogram.increment(tcp_src, packet_length);
    dst_port_histogram.increment(tcp_dst, packet_length);
}

void one_page_report::render(const string &outdir)
{
    string fname = outdir + "/" + filename;

    cairo_surface_t *surface = cairo_pdf_surface_create(fname.c_str(),
				 bounds.width,
				 bounds.height);
    cairo_t *cr = cairo_create(surface);

    //
    // Configure views
    //

    double pad_size = bounds.width * page_margin_factor;
    plot_view::bounds_t pad_bounds(bounds.x + pad_size,
            bounds.y + pad_size, bounds.width - pad_size * 2,
            bounds.height - pad_size * 2);

    // iff a colored common port appears in the time histogram, add its color to the legend
    if(ports_in_time_histogram[PORT_HTTP] ||
            ports_in_time_histogram[PORT_HTTP_ALT_0] ||
            ports_in_time_histogram[PORT_HTTP_ALT_1] ||
            ports_in_time_histogram[PORT_HTTP_ALT_2] ||
            ports_in_time_histogram[PORT_HTTP_ALT_3] ||
            ports_in_time_histogram[PORT_HTTP_ALT_4] ||
            ports_in_time_histogram[PORT_HTTP_ALT_5]) {
        color_labels.push_back(legend_view::entry_t(color_blue, "HTTP", PORT_HTTP));
    }
    if(ports_in_time_histogram[PORT_HTTPS]) {
        color_labels.push_back(legend_view::entry_t(color_green, "HTTPS", PORT_HTTPS));
    }
    if(ports_in_time_histogram[PORT_SSH]) {
        color_labels.push_back(legend_view::entry_t(color_purple, "SSH", PORT_SSH));
    }
    if(ports_in_time_histogram[PORT_FTP_DATA] || ports_in_time_histogram[PORT_FTP_CONTROL]) {
        color_labels.push_back(legend_view::entry_t(color_red, "FTP", PORT_FTP_DATA));
    }
    // assign the top 4 source ports colors if they don't already have them
    vector<port_histogram::port_count>::const_iterator it = src_port_histogram.begin();
    for(size_t count = 0; count < port_colors_count && it != src_port_histogram.end(); it++) {
        port_colormap_t::const_iterator color = port_colormap.find(it->port);
        if(color == port_colormap.end()) {
            string label = ssprintf(generic_legend_format.c_str(), it->port);
            switch(count) {
                case 0:
                    if(ports_in_time_histogram[it->port]) {
                        color_labels.push_back(legend_view::entry_t(color_orange, label, it->port));
                    }
                    port_colormap[it->port] = color_orange;
                    break;
                case 1:
                    if(ports_in_time_histogram[it->port]) {
                        color_labels.push_back(legend_view::entry_t(color_magenta, label, it->port));
                    }
                    port_colormap[it->port] = color_magenta;
                    break;
                case 2:
                    if(ports_in_time_histogram[it->port]) {
                        color_labels.push_back(legend_view::entry_t(color_deep_purple, label, it->port));
                    }
                    port_colormap[it->port] = color_deep_purple;
                    break;
                case 3:
                    if(ports_in_time_histogram[it->port]) {
                        color_labels.push_back(legend_view::entry_t(color_teal, label, it->port));
                    }
                    port_colormap[it->port] = color_teal;
                    break;
                default:
                    break;
            }
            count++;
        }
    }
    sort(color_labels.begin(), color_labels.end());
    
    // time histogram
    double condension_factor = (double) packet_histogram.non_sparse_size() / (double) max_bars;
    if(condension_factor > 1.1) {
        // condense only by whole numbers to avoid messing up bar labels
        packet_histogram.condense(((int) condension_factor) + 1);
    }
    time_histogram_view th_view(packet_histogram, port_colormap, default_color,
            cdf_color);

    // color legend
    legend_view lg_view(color_labels);

    // address histograms
    // histograms are built from iptree here
    address_histogram src_addr_histogram(src_tree);
    address_histogram dst_addr_histogram(dst_tree);
    address_histogram_view src_ah_view(src_addr_histogram);
    if(src_addr_histogram.size() > 0) {
        src_ah_view.title = "Top Source Addresses";
    }
    else {
        src_ah_view.title = "No Source Addresses";
    }
    src_ah_view.bar_color = default_color;
    src_ah_view.cdf_color = cdf_color;
    address_histogram_view dst_ah_view(dst_addr_histogram);
    if(dst_addr_histogram.size() > 0) {
        dst_ah_view.title = "Top Destination Addresses";
    }
    else {
        dst_ah_view.title = "No Destination Addresses";
    }
    dst_ah_view.bar_color = default_color;
    dst_ah_view.cdf_color = cdf_color;

    // port histograms
    port_histogram_view sp_view(src_port_histogram, port_colormap, default_color,
            cdf_color);
    port_histogram_view dp_view(dst_port_histogram, port_colormap, default_color,
            cdf_color);
    if(src_port_histogram.size()) {
        sp_view.title = "Top Source Ports";
    }
    else {
        sp_view.title = "No Source Ports";
    }
    if(dst_port_histogram.size()) {
        dp_view.title = "Top Destination Ports";
    }
    else {
        dp_view.title = "No Destination Ports";
    }

    //
    // run configured views through render pass
    //

    render_pass pass(*this, cr, pad_bounds);

    pass.render_header();
    pass.render(th_view);
    pass.render(lg_view);
    if(getenv("DEBUG")) {
        pass.render_map();
        pass.render_packetfall();
    }
    pass.render(src_ah_view, dst_ah_view);
    pass.render(sp_view, dp_view);

    // cleanup
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
}

void one_page_report::render_pass::render_header()
{
    string formatted;
    // title
    double title_line_space = report.header_font_size * line_space_factor;
    //// version
    render_text_line(title_version, report.header_font_size,
            title_line_space);
    //// input
    formatted = ssprintf("Input: %s", report.source_identifier.c_str());
    render_text_line(formatted.c_str(), report.header_font_size,
            title_line_space);
    //// date generated
    time_t gen_unix = time(0);
    struct tm gen_time = *localtime(&gen_unix);
    formatted = ssprintf("Generated: %04d-%02d-%02d %02d:%02d:%02d",
            1900 + gen_time.tm_year, 1 + gen_time.tm_mon, gen_time.tm_mday,
            gen_time.tm_hour, gen_time.tm_min, gen_time.tm_sec);
    render_text_line(formatted.c_str(), report.header_font_size,
            title_line_space);
    //// trailing pad
    end_of_content += title_line_space * 4;
    // quick stats
    //// date range
    time_t tstart = report.earliest.tv_sec;
    struct tm start;
    memset(&start,0,sizeof(start));
    localtime_r(&tstart,&start);

    time_t tstop = report.latest.tv_sec;
    struct tm stop;
    memset(&stop,0,sizeof(stop));
    localtime_r(&tstop,&stop);
    formatted = ssprintf("Date range: %04d-%02d-%02d %02d:%02d:%02d -- %04d-%02d-%02d %02d:%02d:%02d",
            1900 + start.tm_year, 1 + start.tm_mon, start.tm_mday,
            start.tm_hour, start.tm_min, start.tm_sec,
            1900 + stop.tm_year, 1 + stop.tm_mon, stop.tm_mday,
            stop.tm_hour, stop.tm_min, stop.tm_sec);
    render_text_line(formatted.c_str(), report.header_font_size,
            title_line_space);
    //// packet count/size
    formatted = ssprintf("Packets analyzed: %s (%s)",
            comma_number_string(report.packet_count).c_str(),
            plot_view::pretty_byte_total(report.byte_count).c_str());
    render_text_line(formatted.c_str(), report.header_font_size,
            title_line_space);
    //// protocol breakdown
    uint64_t transport_total = 0;
    for(map<uint32_t, uint64_t>::const_iterator ii =
                report.transport_counts.begin();
            ii != report.transport_counts.end(); ii++) {
        transport_total += ii->second;
    }

    stringstream ss;
    unsigned int percentage = 0;
    uint64_t classified_total = 0;
    ss << "Transports: ";
    if(transport_total > 0) {
        for(vector<transport_type>::const_iterator it = display_transports.begin();
                it != display_transports.end(); it++) {
            uint64_t count = report.transport_counts[it->ethertype];
            classified_total += count;
            percentage = (unsigned int) (((double) count / (double) transport_total) * 100.0);

            if(percentage > 0) {
                ss << it->name << " " << percentage << "% ";
            }
        }
        percentage = (unsigned int) (((double) (transport_total - classified_total) / transport_total) * 100.0);
        if(percentage > 0) {
            ss << "Other " << percentage << "% ";
        }
    }
    formatted = ss.str();
    render_text_line(formatted.c_str(), report.header_font_size,
            title_line_space);
    // trailing pad for entire header
    end_of_content += title_line_space * 4;
}

void one_page_report::render_pass::render_text(string text,
        double font_size, double x_offset,
        cairo_text_extents_t &rendered_extents)
{
    cairo_set_font_size(surface, font_size);
    cairo_set_source_rgb(surface, 0.0, 0.0, 0.0);
    cairo_text_extents(surface, text.c_str(), &rendered_extents);
    cairo_move_to(surface, surface_bounds.x + x_offset, surface_bounds.y +
            end_of_content + rendered_extents.height);
    cairo_show_text(surface, text.c_str());
}

void one_page_report::render_pass::render_text_line(string text,
        double font_size, double line_space)
{
    cairo_text_extents_t extents;
    render_text(text, font_size, 0.0, extents);
    end_of_content += extents.height + line_space;
}

void one_page_report::render_pass::render(time_histogram_view &view)
{
    plot_view::bounds_t bnds(surface_bounds.x,
                             surface_bounds.y + end_of_content,
                             surface_bounds.width,
                             packet_histogram_height);

    view.render(surface, bnds);

    end_of_content += bnds.height * histogram_pad_factor_y;
}

void one_page_report::render_pass::render_packetfall()
{
    plot_view::bounds_t bnds(surface_bounds.x, surface_bounds.y + end_of_content, surface_bounds.width,
            packet_histogram_height);

    report.pfall.render(surface, bnds);

    end_of_content += bnds.height * histogram_pad_factor_y;
}

void one_page_report::render_pass::render_map()
{
    plot_view::bounds_t bnds(surface_bounds.x,
            surface_bounds.y + end_of_content, surface_bounds.width, packet_histogram_height);

    report.netmap.render(surface, bnds);

    end_of_content += bnds.height * histogram_pad_factor_y;
}

void one_page_report::render_pass::render(address_histogram_view &left, address_histogram_view &right)
{
    double width = surface_bounds.width / address_histogram_width_divisor;
    const address_histogram &left_data = left.get_data();
    const address_histogram &right_data = right.get_data();
    uint64_t total_datagrams = left_data.ingest_count();

    plot_view::bounds_t left_bounds(surface_bounds.x, surface_bounds.y +
            end_of_content, width, address_histogram_height);
    left.render(surface, left_bounds);

    plot_view::bounds_t right_bounds(surface_bounds.x + (surface_bounds.width - width),
            surface_bounds.y + end_of_content, width, address_histogram_height);
    right.render(surface, right_bounds);

    end_of_content += max(left_bounds.height, right_bounds.height);

    // text stats
    string stat_line_format = "%d) %s - %s (%d%%)";
    for(size_t ii = 0; ii < report.histogram_show_top_n_text; ii++) {
        cairo_text_extents_t left_extents, right_extents;

        if(left_data.size() > ii && left_data.at(ii).count > 0) {
            const iptree::addr_elem &addr = left_data.at(ii);
            uint8_t percentage = 0;

            percentage = (uint8_t) (((double) addr.count / (double) total_datagrams) * 100.0);

            string str = ssprintf(stat_line_format.c_str(), ii + 1, addr.str().c_str(),
                    plot_view::pretty_byte_total(addr.count).c_str(), percentage);

            render_text(str.c_str(), report.top_list_font_size, left_bounds.x,
                    left_extents);
        }

        if(right_data.size() > ii && right_data.at(ii).count > 0) {
            const iptree::addr_elem &addr = right_data.at(ii);
            uint8_t percentage = 0;

            percentage = (uint8_t) (((double) addr.count / (double) total_datagrams) * 100.0);

            string str = ssprintf(stat_line_format.c_str(), ii + 1, addr.str().c_str(),
                    plot_view::pretty_byte_total(addr.count).c_str(), percentage);

            render_text(str.c_str(), report.top_list_font_size, right_bounds.x,
                    right_extents);
        }

        if((left_data.size() > ii && left_data.at(ii).count > 0) ||
                (right_data.size() > ii && right_data.at(ii).count > 0)) {
            end_of_content += max(left_extents.height, right_extents.height) * 1.5;
        }
    }

    end_of_content += max(left_bounds.height, right_bounds.height) *
        (histogram_pad_factor_y - 1.0);
}

void one_page_report::render_pass::render(port_histogram_view &left, port_histogram_view &right)
{
    port_histogram &left_data = left.get_data();
    port_histogram &right_data = right.get_data();

    uint64_t total_bytes = left_data.ingest_count();

    double width = surface_bounds.width / address_histogram_width_divisor;

    plot_view::bounds_t left_bounds(surface_bounds.x, surface_bounds.y + end_of_content,
            width, port_histogram_height);
    left.render(surface, left_bounds);

    plot_view::bounds_t right_bounds(surface_bounds.x + (surface_bounds.width - width),
            surface_bounds.y + end_of_content, width, port_histogram_height);
    right.render(surface, right_bounds);

    end_of_content += max(left_bounds.height, right_bounds.height);

    // text stats
    string stat_line_format = "%d) %d - %s (%d%%)";
    for(size_t ii = 0; ii < report.histogram_show_top_n_text; ii++) {
        cairo_text_extents_t left_extents, right_extents;

        if(left_data.size() > ii && left_data.at(ii).count > 0) {
            port_histogram::port_count port = left_data.at(ii);
            uint8_t percentage = 0;

            percentage = (uint8_t) (((double) port.count / (double) total_bytes) * 100.0);

            string str = ssprintf(stat_line_format.c_str(), ii + 1, port.port,
                    plot_view::pretty_byte_total(port.count).c_str(), percentage);

            render_text(str.c_str(), report.top_list_font_size, left_bounds.x,
                    left_extents);
        }

        if(right_data.size() > ii && right_data.at(ii).count > 0) {
            port_histogram::port_count port = right_data.at(ii);
            uint8_t percentage = 0;

            percentage = (uint8_t) (((double) port.count / (double) total_bytes) * 100.0);

            string str = ssprintf(stat_line_format.c_str(), ii + 1, port.port,
                    plot_view::pretty_byte_total(port.count).c_str(), percentage);

            render_text(str.c_str(), report.top_list_font_size, right_bounds.x,
                    right_extents);
        }

        if((left_data.size() > ii && left_data.at(ii).count > 0) ||
                (right_data.size() > ii && right_data.at(ii).count > 0)) {
            end_of_content += max(left_extents.height, right_extents.height) * 1.5;
        }
    }

    end_of_content += max(left_bounds.height, right_bounds.height) *
        (histogram_pad_factor_y - 1.0);
}

void one_page_report::render_pass::render(const legend_view &view)
{
    plot_view::bounds_t view_bounds(surface_bounds.x, surface_bounds.y + end_of_content,
            surface_bounds.width, legend_height);
    view.render(surface, view_bounds);

    end_of_content += legend_height;
}

vector<one_page_report::transport_type> one_page_report::build_display_transports()
{
    vector<transport_type> v;
    v.push_back(transport_type(ETHERTYPE_IP, "IPv4"));
    v.push_back(transport_type(ETHERTYPE_IPV6, "IPv6"));
    v.push_back(transport_type(ETHERTYPE_ARP, "ARP"));
    v.push_back(transport_type(ETHERTYPE_VLAN, "VLAN"));
    return v;
}

void one_page_report::dump(int dbg)
{
    if(dbg){
        std::cout << "src_tree:\n" << src_tree << "\n" << "dst_tree:\n" << dst_tree << "\n";
    }
}

#endif
