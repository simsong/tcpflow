/**
 * time_histogram_view.cpp: 
 * Make fancy time histograms
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_LIBCAIRO

#include "time_histogram_view.h"

time_histogram_view::time_histogram_view(const time_histogram &histogram_,
        const colormap_t &port_colors_, const rgb_t &default_color_,
        const rgb_t &cdf_color_) :
    histogram(histogram_), port_colors(port_colors_), default_color(default_color_),
    cdf_color(cdf_color_)
{
    title = "";
    subtitle = "";
    pad_left_factor = 0.2;
    pad_top_factor = 0.1;
    y_tick_font_size = 6.0;
    right_tick_font_size = 6.0;
    x_axis_font_size = 8.0;
    x_axis_decoration = plot_view::AXIS_SPAN_STOP;
    y_label = "packets";
}

const uint8_t time_histogram_view::y_tick_count = 5;
const double time_histogram_view::bar_space_factor = 1.2;
const double time_histogram_view::cdf_line_width = 0.5;
const vector<time_histogram_view::time_unit> time_histogram_view::time_units =
        time_histogram_view::build_time_units();
const vector<time_histogram_view::si_prefix> time_histogram_view::si_prefixes =
        time_histogram_view::build_si_prefixes();
const double time_histogram_view::blank_bar_line_width = 0.25;
const time_histogram_view::rgb_t time_histogram_view::blank_bar_line_color(0.0, 0.0, 0.0);

void time_histogram_view::render(cairo_t *cr, const bounds_t &bounds)
{
    //
    // create x label based on duration of capture
    //
    uint64_t bar_interval = histogram.usec_per_bucket() / (1000 * 1000);
    time_t duration = histogram.end_date() - histogram.start_date();
    if(histogram.packet_count() == 0) {
        x_label = "no packets received";
        x_axis_decoration = plot_view::AXIS_SPAN_STOP;
    }
    else {
        stringstream ss;
        // how long does is the total capture?
        if(duration < 1) {
            ss << "<1 second";
        }
        else {
            // the total time is represented by the two (or one) coursest appropriate units
            // example:
            //     5 hours, 10 minutes
            //     58 seconds
            // but never:
            //     5 hours. 10 minutes, 30 seconds

            // break the duration down into its constituent parts
            vector<uint64_t> duration_values;
            vector<string> duration_names;
            int remainder = duration;
            for(vector<time_unit>::const_reverse_iterator it = time_units.rbegin();
                    it != time_units.rend(); it++) {

                duration_values.push_back(remainder / it->seconds);
                duration_names.push_back(it->name);
                remainder %= it->seconds;
            }

            int print_count = 0;
            // find how many time units are worth printing (for comma insertion)
            for(vector<uint64_t>::const_iterator it = duration_values.begin();
                    it != duration_values.end(); it++) {
                if(*it > 0) {
                    print_count++;
                }
                // if we've seen a nonzero unit, and now a zero unit, abort because skipping
                // a unit is weird (2 months, 1 second)
                else if(print_count > 0) {
                    break;
                }
            }

            // work back through the values and print the two coursest nonzero
            print_count = min(print_count, 2);
            int printed = 0;
            for(size_t ii = 0; ii < time_units.size(); ii++) {
                string name = duration_names.at(ii);
                uint64_t value = duration_values.at(ii);

                // skip over insignificant units
                if(value == 0 && printed == 0) {
                    continue;
                }
                printed++;

                // don't actually print intermediate zero values (no 3 hours, 0 minutes, 30 seconds)
                if(value > 0) {
                    ss << value << " " << name;
                }
                if(value > 1) {
                    ss << "s";
                }
                if(printed < print_count) {
                    ss << ", ";
                }

                if(printed == print_count) {
                    break;
                }
            }
        }

        // how long does each bar represent?
        if(bar_interval < 1 && duration >= 1) {
            ss << " (<1 second intervals)";
        }
        else if(bar_interval >= 1) {
            string interval_name;
            uint64_t interval_value = 0;
            for(vector<time_unit>::const_iterator it = time_units.begin();
                    it != time_units.end(); it++) {
                
                if(it + 1 == time_units.end() || bar_interval < (it+1)->seconds) {
                    interval_name = it->name;
                    interval_value = bar_interval / it->seconds;
                    break;
                }

            }

            ss << " (" << interval_value << " " << interval_name << " intervals)";
        }
        x_label = ss.str();
    }

    //
    // choose y axis tick labels
    //

    // scale raw bucket totals

    uint8_t unit_log_1000 = (uint8_t) (log(histogram.tallest_bar()) / log(1000));
    if(unit_log_1000 >= si_prefixes.size()) {
        unit_log_1000 = 0;
    }
    si_prefix unit = si_prefixes.at(unit_log_1000);
    double y_scale_range = histogram.tallest_bar() / (double) unit.magnitude;
    double y_scale_interval = y_scale_range / (y_tick_count - 1);

    uint64_t next_value = 0;
    for(int ii = 0; ii < y_tick_count; ii++) {
        uint64_t value = next_value;
        double next_raw_value = (ii + 1) * y_scale_interval;
        next_value = (uint64_t) floor(next_raw_value + 0.5);

        if(value == next_value && ii < y_tick_count - 1) {
            continue;
        }

        string label = ssprintf("%d%s", value, unit.prefix.c_str());

	y_tick_labels.push_back(label);
    }

    right_tick_labels.push_back("0%");
    right_tick_labels.push_back("100%");

    plot_view::render(cr, bounds);
}

void time_histogram_view::render_data(cairo_t *cr, const bounds_t &bounds)
{
    size_t bars = histogram.non_sparse_size();
    double bar_allocation = bounds.width / (double) bars; // bar width with spacing
    double bar_width = bar_allocation / bar_space_factor; // bar width as rendered
    double bar_leading_pad = (bar_allocation - bar_width) / 2.0;
    time_histogram::histogram_map::buckets_t::const_iterator it = histogram.begin();

    if(it == histogram.end()) {
        return;
    }

    uint32_t first_offset = it->first;
    double tallest_bar = (double) histogram.tallest_bar();

    for(; it != histogram.end(); it++) {
        double bar_height = (double) it->second->sum() / tallest_bar * bounds.height;
        double bar_x = bounds.x + (it->first - first_offset) * bar_allocation + bar_leading_pad;
        double bar_y = bounds.y + (bounds.height - bar_height);
        bounds_t bar_bounds(bar_x, bar_y, bar_width, bar_height);

        bucket_view bar(*it->second, port_colors, default_color);

        bar.render(cr, bar_bounds);
    }

    // CDF
    double accumulator = 0.0;
    double histogram_sum = (double) histogram.packet_count();
    cairo_move_to(cr, bounds.x, bounds.y + bounds.height);
    for(size_t ii = 0; ii < bars; ii++) {
        const time_histogram::bucket bkt = histogram.at(ii + first_offset);
        accumulator += (double) bkt.sum() / histogram_sum;

        double x = bounds.x + ii * bar_allocation;
        double next_x = x + bar_allocation;
        double y = bounds.y + (1.0 - accumulator) * bounds.height;

        // don't draw over the left-hand y axis
        if(ii == 0) {
            cairo_move_to(cr, x, y);
        }
        else {
            cairo_line_to(cr, x, y);
        }
        cairo_line_to(cr, next_x, y);
    }
    cairo_set_source_rgb(cr, cdf_color.r, cdf_color.g, cdf_color.b);
    cairo_set_line_width(cr, cdf_line_width);
    cairo_stroke(cr);
}

vector<time_histogram_view::time_unit> time_histogram_view::build_time_units()
{
    vector<time_unit> output;

    output.push_back(time_unit("second", 1L));
    output.push_back(time_unit("minute", 60L));
    output.push_back(time_unit("hour", 60L * 60L));
    output.push_back(time_unit("day", 60L * 60L * 24L));
    output.push_back(time_unit("week", 60L * 60L * 24L * 7L));
    output.push_back(time_unit("month", 60L * 60L * 24L * 30L));
    output.push_back(time_unit("year", 60L * 60L * 24L * 365L));

    return output;
}

vector<time_histogram_view::si_prefix> time_histogram_view::build_si_prefixes()
{
    vector<si_prefix> output;

    output.push_back(si_prefix("", 1LL));
    output.push_back(si_prefix("K", 1000LL));
    output.push_back(si_prefix("M", 1000LL * 1000LL));
    output.push_back(si_prefix("G", 1000LL * 1000LL * 1000LL));
    output.push_back(si_prefix("T", 1000LL * 1000LL * 1000LL * 1000LL));
    output.push_back(si_prefix("P", 1000LL * 1000LL * 1000LL * 1000LL * 1000LL));
    output.push_back(si_prefix("E", 1000LL * 1000LL * 1000LL * 1000LL * 1000LL * 1000LL));

    return output;
}

// bucket view

void time_histogram_view::bucket_view::render(cairo_t *cr, const bounds_t &bounds)
{
    // how far up the bar have we rendered so far?
    double total_height = bounds.y + bounds.height;

    // if multiple sections of the same color follow, simply accumulate their height
    double height_accumulator = 0.0;
    rgb_t next_color = default_color;

    for(map<time_histogram::port_t, time_histogram::count_t>::const_iterator it = bucket.counts.begin();
            it != bucket.counts.end();) {

        double height = bounds.height * ((double) it->second / (double) bucket.sum());

        // on first section, preload the first color as the 'next' color
        if(it == bucket.counts.begin()) {
            colormap_t::const_iterator color_pair = color_map.find(it->first);
            if(color_pair != color_map.end()) {
                next_color = color_pair->second;
            }
        }

        // advance to the next color
        rgb_t color = next_color;
        next_color = default_color;

        // if there's a next bucket, get its color for the next color
        // next consolidate this section with the next if the colors match
        it++;
        if(it != bucket.counts.end()) {
            colormap_t::const_iterator color_pair = color_map.find(it->first);
            if(color_pair != color_map.end()) {
                next_color = color_pair->second;
            }

            if(color == next_color) {
                height_accumulator += height;
                continue;
            }
        }

        cairo_set_source_rgb(cr, color.r, color.g, color.b);

        // account for consolidated sections
        height += height_accumulator;
        height_accumulator = 0.0;

        cairo_rectangle(cr, bounds.x, total_height - height, bounds.width, height);
        cairo_fill(cr);

        total_height -= height;
    }

    // non-TCP packets
    if(bucket.portless_count > 0) {
        double height = bounds.height * ((double) bucket.portless_count / (double) bucket.sum());
        cairo_set_source_rgb(cr, blank_bar_line_color.r, blank_bar_line_color.g, blank_bar_line_color.b);
        double offset = blank_bar_line_width / 2;
        cairo_set_line_width(cr, blank_bar_line_width);
        cairo_rectangle(cr, bounds.x + offset, total_height - height + offset,
                bounds.width - blank_bar_line_width, height - blank_bar_line_width);
        cairo_stroke(cr);
    }
}

#endif
