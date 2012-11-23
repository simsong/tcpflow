/**
 * time_histogram.cpp: 
 * Make fancy time histograms
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"

#include <math.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <vector>

#include "time_histogram.h"

using namespace std;

#define IPV6_HEADER_LEN 40
#define PORT_HTTP 80
#define PORT_HTTPS 443

// copied from tcpdemux.cpp - should this be in a header somewhere?
struct private_ip6_hdr {
    union {
	struct ip6_hdrctl {
	    uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
	    uint16_t ip6_un1_plen;	/* payload length */
	    uint8_t  ip6_un1_nxt;	/* next header */
	    uint8_t  ip6_un1_hlim;	/* hop limit */
	} ip6_un1;
	uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    struct private_in6_addr ip6_src;	/* source address */
    struct private_in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

time_histogram::graph_config_t default_graph_config = {
    /* filename */ "graph",
    /* title */ "graph of things",
    /* subtitle */ "x vs y",
    /* width */ 161.803,
    /* height */ 100.000,
    /* title_font_size */ 8.0,
    /* title_max_width_ratio */ 0.8,
    /* title_y_pad_factor */ 2.0,
    /* subtitle_y_pad_factor */ 0.2,
    /* subtitle_font_size_factor */ 0.4,
    /* tick_length */ 2.0,
    /* tick_width */ 0.2,
    /* x_tick_count */ 5,
    /* y_tick_count */ 5,
    /* x_tick_label_max_len */ 64,
    /* y_tick_label_max_len */ 8,
    /* x_tick_label_dummy */ "000.00",
    /* y_tick_label_dummy */ "000.00",
    /* x_tick_label_pad_factor */ 2.5,
    /* y_tick_label_pad_factor */ 2.0,
    /* y_tick_font_size */ 3.0,
    /* x_tick_font_size */ 3.0,
    /* pad_bottom */ 8.0,
    /* pad_right */ 24.0,
    /* legend_chip_edge_length */ 4.0,
    /* legend_font_size */ 2.5
};

const time_histogram::histogram_config_t time_histogram::default_histogram_config = {
    /* graph */ default_graph_config,
    /* bar_space_factor */ 1.2,
    /* bucket_count */ 600,
    /* first_bucket_factor */ 0.1,
};

// Unit in libpcap is microsecond, so shall it be here
const uint64_t time_histogram::span_lengths[] = {
    /* minute */ 60L * 1000L * 1000L,
    /* hour */ 60L * 60L * 1000L * 1000L,
    /* day */ 24L * 60L * 60L * 1000L * 1000L,
    /* week */ 7L * 24L * 60L * 60L * 1000L * 1000L,
    /* month */ 30L * 24L * 60L * 60L * 1000L * 1000L,
    /* year */ 12L * 30L * 24L * 60L * 60L * 1000L * 1000L
};

const char * units_strings[] = {
    "packets vs time",
    "kilopackets vs time",
    "megapackets vs time",
    "gigapackets vs time",
    "terapackets vs time",
    "petapackets vs time",
    "exapackets vs time",
};


//
// Helper functions
//

void ss_time_format(struct tm *time, stringstream *ss)
{
    (*ss) << setfill('0');
    (*ss) << setw(4) << (1900 + time->tm_year) << "-";
    (*ss) << setw(2) << (1 + time->tm_mon) << "-";
    (*ss) << setw(2) << time->tm_mday << " ";
    (*ss) << setw(2) << time->tm_hour << ":";
    (*ss) << setw(2) << time->tm_min << ":";
    (*ss) << setw(2) << time->tm_sec;
}

void time_format(struct tm *time, char *buf, int buflen)
{
    snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d", 1900 + time->tm_year,
	     1 + time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min,
	     time->tm_sec);
}

// quickly try and get the port out of the packet.  It is assumed that the
// packet is an IPv4 or 6 datagram in an ethernet frame.
// any and all errors simply result in -1 being returned
int get_tcp_port(const packet_info &pi)
{
    // keep track of the length of the packet not yet examined
    unsigned int unused_len = pi.caplen;
    if(unused_len < sizeof(struct ether_header)) {
        return -1;
    }
/* MAC layer now handled in caller. pi.data is an IPv4 or IPv6 packet */
#if 0
    unused_len -= sizeof(struct ether_header);

    struct ether_header *eth_header = (struct ether_header *) p;
    u_short *ether_type_location = &eth_header->ether_type;
    const u_char *ether_data = p + sizeof(struct ether_header);

    /* Handle basic VLAN packets */
    if(ntohs(*ether_type_location) == ETHERTYPE_VLAN) {
        // skip to real ethertype
        ether_type_location += 2;
        ether_data += 4;
        unused_len -= 4;
    }
#endif
    // only one of these is safe to use!
#pragma GCC diagnostic ignored "-Wcast-align"
    const struct ip *ip_header = (struct ip *) pi.data;
#pragma GCC diagnostic warning "-Wcast-align"
    const struct private_ip6_hdr *ip6_header = (struct private_ip6_hdr *) pi.data;

    u_char *ip_data=0;

    switch(ip_header->ip_v){
    case 4:				// IPv4
	if(unused_len < sizeof(struct ip) ||
	   ip_header->ip_p != IPPROTO_TCP) {
	    return -1;
	}
	unused_len -= sizeof(struct ip);
	ip_data = (u_char *) pi.data + sizeof(struct ip);
	break;
    case 6:				// IPv6
	if(unused_len < sizeof(struct private_ip6_hdr) ||
	   ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
	    return -1;
	}
	unused_len -= sizeof(struct private_ip6_hdr);
	ip_data = (u_char *) pi.data + sizeof(struct private_ip6_hdr);
	break;
    default:
	return -1;
    }

    if(unused_len < sizeof(struct tcphdr)) {
        return -1;
    }

#pragma GCC diagnostic ignored "-Wcast-align"
    struct tcphdr *tcp_header = (struct tcphdr *) ip_data;
#pragma GCC diagnostic warning "-Wcast-align"

    return ntohs(tcp_header->th_dport);
}

//
// Rendering classes
//

class plotter {
private:
    plotter() { }			// don't allow instances to be made...
public:
    // render title
    static void render(cairo_t *cr, const ticks_t &ticks, const legend_t &legend, const time_histogram::graph_config_t &conf) {
#ifdef HAVE_LIBCAIRO
        cairo_text_extents_t title_extents;
        cairo_text_extents_t subtitle_extents;
        double font_size_title = conf.title_font_size;

        cairo_select_font_face(cr, "Sans",
			       CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, font_size_title);
        cairo_set_source_rgb(cr, 0, 0, 0);
        cairo_text_extents(cr, conf.title, &title_extents);
        // Is the title too wide?
        double title_max_width = conf.width *
            conf.title_max_width_ratio;
        if(title_extents.width > title_max_width) {
            // scale the font size accordingly
            font_size_title *= title_max_width / title_extents.width;
            cairo_text_extents(cr, conf.title, &title_extents);
        }
        // derive subtitle size and measure
        double font_size_subtitle = font_size_title *
            conf.subtitle_font_size_factor;
        cairo_set_font_size(cr, font_size_subtitle);
        cairo_text_extents(cr, conf.subtitle, &subtitle_extents);
        double intertitle_padding = subtitle_extents.height *
            conf.subtitle_y_pad_factor;
        cairo_set_font_size(cr, font_size_title);
        double title_padded_height = title_extents.height *
            conf.title_y_pad_factor;
        double titles_padded_height = title_padded_height +
            intertitle_padding + subtitle_extents.height;
        // render title text
        cairo_move_to(cr, (conf.width - title_extents.width) / 2.0,
		      title_extents.height +
		      (title_padded_height - title_extents.height) / 2);
        cairo_show_text(cr, conf.title);
        // render subtitle text
        cairo_set_font_size(cr, font_size_subtitle);
        cairo_move_to(cr, (conf.width - subtitle_extents.width) / 2.0,
		      ((title_padded_height - title_extents.height) / 2) +
		      title_extents.height + intertitle_padding +
		      subtitle_extents.height);
        cairo_show_text(cr, conf.subtitle);

        // render ticks

        // y ticks (packet counts)

        // find longest label and pad for it
        cairo_text_extents_t label_extents;
        cairo_set_font_size(cr, conf.y_tick_font_size);
        double max_label_width = 0.0;
        for(size_t ii = 0; ii < ticks.y_labels.size(); ii++) {
            cairo_text_extents(cr, ticks.y_labels.at(ii).c_str(),
			       &label_extents);
            if(label_extents.width > max_label_width) {
                max_label_width = label_extents.width;
            }
        }
        double y_label_allotment = max_label_width *
            conf.y_tick_label_pad_factor;
        double left_padding = y_label_allotment + conf.tick_length;

        // translate down so the top of the window aligns with the top of
        // the graph itself
        cairo_translate(cr, 0, titles_padded_height);

        double y_height = conf.height - conf.pad_bottom;
        double y_tick_spacing = y_height / ticks.y_labels.size();
        for(size_t ii = 0; ii < ticks.y_labels.size(); ii++) {
            //double yy = (ii * y_tick_spacing) - (conf.tick_width / 2);
            double yy = (ii * y_tick_spacing);

            cairo_text_extents(cr, ticks.y_labels.at(ii).c_str(),
			       &label_extents);
            cairo_move_to(cr, (y_label_allotment - label_extents.width) / 2,
			  yy + (label_extents.height / 2));
            cairo_show_text(cr, ticks.y_labels.at(ii).c_str());

            // tick mark (but not for 0)
            if(ii < ticks.y_labels.size() - 1) {
                cairo_rectangle(cr, y_label_allotment,
				yy + (conf.tick_width / 2),
				conf.tick_length, conf.tick_width);
                cairo_fill(cr);
            }
        }
        cairo_identity_matrix(cr);

        // x ticks (time)
        // TODO prevent overlap

        cairo_set_font_size(cr, conf.x_tick_font_size);

        cairo_translate(cr, left_padding, conf.height - conf.pad_bottom);

        double x_width = conf.width - (conf.pad_right + left_padding);
        double x_tick_spacing = x_width / (ticks.x_labels.size() - 1);

        for(size_t ii = 0; ii < ticks.x_labels.size(); ii++) {
            double xx = ii * x_tick_spacing;

            const char *label = ticks.x_labels.at(ii).c_str();

            cairo_text_extents(cr, label, &label_extents);
            double pad = ((label_extents.height *
			   conf.x_tick_label_pad_factor) -
			  label_extents.height) / 2;

            // prevent labels from running off the edge of the image
            double label_x = xx - (label_extents.width / 2.0);
            label_x = max(label_x, -left_padding);
            label_x = min(conf.width - label_extents.width, label_x);

            cairo_move_to(cr, label_x, label_extents.height + pad);
            cairo_show_text(cr, label);
        }

        cairo_identity_matrix(cr);

        // render legend

        cairo_translate(cr, conf.width - (conf.pad_right * 0.9),
			titles_padded_height);

        cairo_text_extents_t legend_label_extents;

        cairo_set_font_size(cr, conf.legend_font_size);

        for(size_t ii = 0; ii < legend.size(); ii++) {
            legend_entry_t entry = legend.at(ii);

            // chip
            cairo_set_source_rgb(cr, entry.color.r, entry.color.g,
				 entry.color.b);
            cairo_rectangle(cr, 0, 0, conf.legend_chip_edge_length,
			    conf.legend_chip_edge_length);
            cairo_fill(cr);

            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, entry.label.c_str(),
			       &legend_label_extents);
            cairo_move_to(cr, conf.legend_chip_edge_length * 1.2,
			  (conf.legend_chip_edge_length / 2.0) +
			  (legend_label_extents.height / 2.0));
            cairo_show_text(cr, entry.label.c_str());

            // translate down for the next legend entry
            cairo_translate(cr, 0, conf.legend_chip_edge_length);
        }

        cairo_set_source_rgb(cr, 0, 0, 0);
        cairo_identity_matrix(cr);

        // transform to render within the graph itself (inside title and
        // labels)
        cairo_translate(cr, left_padding,
			titles_padded_height);
        cairo_scale(cr,
		    1.0 - ((left_padding + conf.pad_right) / conf.width),
		    1.0 -
		    ((titles_padded_height + conf.pad_bottom) / conf.height));
#endif
    }
};

void time_histogram::ingest_packet(const packet_info &pi)
{
    uint64_t time = pi.ts.tv_usec + pi.ts.tv_sec * 1000000L; // microsecondsx
    // if we haven't received any data yet, we need to set the base time
    if(!received_data) {
	uint64_t first_bucket = (uint64_t) ((double) conf.bucket_count *
					    conf.first_bucket_factor);
	base_time = time - (bucket_width * first_bucket);
	received_data = true;
    }

    int target_index = (time - base_time) / bucket_width;

    if(target_index < 0) {
	underflow_count++;
	return;
    }
    if(target_index >= conf.bucket_count) {
	overflow_count++;
	return;
    }

    bucket_t *target_bucket = &buckets.at(target_index);

    switch(get_tcp_port(pi)) {
    case PORT_HTTP:
	target_bucket->http++;
	break;
    case PORT_HTTPS:
	target_bucket->https++;
	break;
    case -1:
	// get_tcp_port() returns -1 for any error, including if
	// there isn't a TCP segment in the packet
	break;
    default:
	target_bucket->other++;
    }
}

void time_histogram::render(const std::string &outdir)
{
    render_vars vars;

    render_prep(vars);

    // if there aren't any significant buckets, abort.
    if(vars.num_sig_buckets < 1) {
	return;
    }

    ticks_t ticks = build_tick_labels(vars);
    legend_t legend = build_legend(vars);

    //
    // Start rendering
    //

#ifdef HAVE_CAIRO_CAIRO_H
    cairo_t *cr;
    cairo_surface_t *surface;
    std::string fname = outdir + "/" + conf.graph.filename;

    surface = cairo_pdf_surface_create(fname.c_str(),
				 conf.graph.width,
				 conf.graph.height);
    cr = cairo_create(surface);

    // have the plotter class do labeling, axes, legend etc and scale
    // our surface to fit within them
    plotter::render(cr, ticks, legend, conf.graph);

    render_bars(cr, vars);

    // reset translation
    cairo_identity_matrix(cr);
     
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
#endif
}

void time_histogram::render_prep(render_vars &vars)
{
    // initial stat sweep:
    //   - how many significant buckets are there
    //     (between the first and last nonzero bucket)
    //   - What is the tallest bucket?
    int index = 0;
    vars.first_index = -1;
    vars.last_index = -1;
    vars.num_sig_buckets = 0;
    vars.greatest_bucket_sum = 0;
    for(vector<bucket_t>::iterator bucket = buckets.begin();
	bucket != buckets.end(); bucket++) {
	uint64_t bucket_sum = (*bucket).http + (*bucket).https
	    + (*bucket).other;

	// look for first and last significant bucket
	if(bucket_sum > 0) {
	    vars.last_index = index;
	    if(vars.first_index < 0) {
		vars.first_index = index;
	    }
	}

	// look for tallest bucket (most packets)
	if(bucket_sum > vars.greatest_bucket_sum) {
	    vars.greatest_bucket_sum = bucket_sum;
	}

	index++;
    }
    vars.num_sig_buckets = vars.last_index - vars.first_index;

    // choose subtitle based on magnitude of units
    conf.graph.subtitle = units_strings[0];
    vars.unit_log_1000 =
	(uint64_t) (log(vars.greatest_bucket_sum) / log(1000));
    if(vars.unit_log_1000 < (sizeof(units_strings) / sizeof(char *))) {
	conf.graph.subtitle = units_strings[vars.unit_log_1000];
    }
}

ticks_t time_histogram::build_tick_labels(render_vars &vars)
{
    ticks_t ticks;
    stringstream formatted;

    // y ticks (packet count)

    // scale raw bucket totals

    double y_scale_range = vars.greatest_bucket_sum /
	pow(1000.0, (double) vars.unit_log_1000);
    double y_scale_interval = y_scale_range /
	(conf.graph.y_tick_count - 1);

    for(int ii = 0; ii < conf.graph.y_tick_count; ii++) {
	formatted << setprecision(2) << fixed;
	formatted << ((conf.graph.y_tick_count - (ii + 1)) *
		      y_scale_interval);

	ticks.y_labels.push_back(formatted.str());

	formatted.str(string());
    }

    // x ticks (localtime)

    const time_t start_unix = (base_time +
			       (bucket_width * vars.first_index)) / (1000 * 1000);
    const time_t stop_unix = (base_time +
			      (bucket_width * vars.last_index)) / (1000 * 1000);
    struct tm start_time = *localtime(&start_unix);
    struct tm stop_time = *localtime(&stop_unix);
        
    ss_time_format(&start_time, &formatted);
    ticks.x_labels.push_back(formatted.str());
    formatted.str(string());
    ss_time_format(&stop_time, &formatted);
    ticks.x_labels.push_back(formatted.str());
    formatted.str(string());

    return ticks;
}

legend_t time_histogram::build_legend(render_vars &vars)
{
    legend_t legend;

    legend.push_back(legend_entry_t(color_http, "HTTP"));
    legend.push_back(legend_entry_t(color_https, "HTTPS"));
    legend.push_back(legend_entry_t(color_other, "Other"));

    return legend;
}

void time_histogram::render_bars(cairo_t *cr, render_vars &vars)
{
#ifdef HAVE_LIBCAIRO
    double offset_unit = conf.graph.width / vars.num_sig_buckets;
    double bar_width = offset_unit / conf.bar_space_factor;
    int index = 0;
    for(vector<bucket_t>::iterator bucket =
	    buckets.begin() + vars.first_index;
	bucket != buckets.begin() + vars.last_index; bucket++) {
	uint64_t bucket_sum = (*bucket).http + (*bucket).https
	    + (*bucket).other;
	double bar_height = (((double) bucket_sum)
			     / ((double) vars.greatest_bucket_sum)) * conf.graph.height;

	if(bar_height > 0) {
	    double http_height = (((double) bucket->http) /
				  ((double) bucket_sum)) * bar_height;
	    double https_height = (((double) bucket->https) /
				   ((double) bucket_sum)) * bar_height;
	    double other_height = (((double) bucket->other) /
				   ((double) bucket_sum)) * bar_height;

	    double current_height = conf.graph.height - bar_height;

	    // HTTP (blue)
	    cairo_set_source_rgb(cr, color_http.r, color_http.g,
				 color_http.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, http_height);
	    cairo_fill(cr);

	    current_height += http_height;

	    // HTTPS (green)
	    cairo_set_source_rgb(cr, color_https.r, color_https.g,
				 color_https.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, https_height);
	    cairo_fill(cr);

	    current_height += https_height;

	    // other (yellow)
	    cairo_set_source_rgb(cr, color_other.r, color_other.g,
				 color_other.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, other_height);
	    cairo_fill(cr);

	    // reset to black
	    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
	}
	index++;
    }
#endif
}



