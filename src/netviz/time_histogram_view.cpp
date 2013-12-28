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
    cdf_color(cdf_color_), bar_time_unit(), bar_time_value(), bar_time_remainder()
{
    title = "";
    subtitle = "";
    pad_left_factor = 0.2;
    pad_top_factor = 0.1;
    y_tick_font_size = 5.0;
    right_tick_font_size = 6.0;
    x_axis_font_size = 8.0;
    x_axis_decoration = plot_view::AXIS_SPAN_STOP;
    y_label = "";
}

const uint8_t time_histogram_view::y_tick_count = 5;
const double time_histogram_view::bar_space_factor = 1.2;
const double time_histogram_view::cdf_line_width = 0.5;
const std::vector<time_histogram_view::time_unit> time_histogram_view::time_units =
        time_histogram_view::build_time_units();
const std::vector<time_histogram_view::si_prefix> time_histogram_view::si_prefixes =
        time_histogram_view::build_si_prefixes();
const double time_histogram_view::blank_bar_line_width = 0.25;
const time_histogram_view::rgb_t time_histogram_view::blank_bar_line_color(0.0, 0.0, 0.0);
const double time_histogram_view::bar_label_font_size = 6.0;
const double time_histogram_view::bar_label_width_factor = 0.8;
const time_histogram_view::rgb_t time_histogram_view::bar_label_normal_color(0.0, 0.0, 0.0);
const time_histogram_view::rgb_t time_histogram_view::bar_label_highlight_color(0.86, 0.08, 0.24);

void time_histogram_view::render(cairo_t *cr, const bounds_t &bounds)
{
    //
    // create x label based on duration of capture
    //
    uint64_t bar_interval = histogram.usec_per_bucket() / (1000 * 1000);
    // add a second to duration; considering a partial second a second makes
    // edge cases look nicer
    time_t duration = histogram.end_date() - histogram.start_date() + 1;
    if(histogram.packet_count() == 0) {
        x_label = "no packets received";
        x_axis_decoration = plot_view::AXIS_SPAN_STOP;
    }
    else {
        std::stringstream ss;
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
            std::vector<uint64_t> duration_values;
            std::vector<std::string> duration_names;
            int remainder = duration;
            for(std::vector<time_unit>::const_reverse_iterator it = time_units.rbegin();
                    it != time_units.rend(); it++) {

                duration_values.push_back(remainder / it->seconds);
                duration_names.push_back(it->name);
                remainder %= it->seconds;
            }

            int print_count = 0;
            // find how many time units are worth printing (for comma insertion)
            for(std::vector<uint64_t>::const_iterator it = duration_values.begin();
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
            print_count = std::min(print_count, 2);
            int printed = 0;
            for(size_t ii = 0; ii < time_units.size(); ii++) {
                std::string name = duration_names.at(ii);
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
            for(std::vector<time_unit>::const_iterator it = time_units.begin();
                    it != time_units.end(); it++) {
                
                if(it + 1 == time_units.end() || bar_interval < (it+1)->seconds) {
                    bar_time_unit = it->name;
                    bar_time_value = bar_interval / it->seconds;
                    bar_time_remainder = bar_interval % it->seconds;
                    break;
                }

            }

            ss << " (";
            if(bar_time_remainder != 0) {
                ss << "~";
            }
            ss << bar_time_value << " " << bar_time_unit << " intervals)";
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

        std::string label = ssprintf("%d %sB", value, unit.prefix.c_str());

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

    unsigned bar_label_numeric = 0;
    int distinct_label_count = 0;
    // choose initial bar value
    if(bar_time_unit.length() > 0) {
        time_t start = histogram.start_date();
        struct tm start_time = *localtime(&start);
        if(bar_time_unit == SECOND_NAME) {
            bar_label_numeric = start_time.tm_sec;
            distinct_label_count = 60;
        }
        else if(bar_time_unit == MINUTE_NAME) {
            bar_label_numeric = start_time.tm_min;
            distinct_label_count = 60;
        }
        else if(bar_time_unit == HOUR_NAME) {
            bar_label_numeric = start_time.tm_hour;
            distinct_label_count = 24;
        }
        else if(bar_time_unit == DAY_NAME) {
            bar_label_numeric = start_time.tm_wday;
            distinct_label_count = 7;
        }
        else if(bar_time_unit == MONTH_NAME) {
            bar_label_numeric = start_time.tm_mon;
            distinct_label_count = 12;
        }
        else if(bar_time_unit == YEAR_NAME) {
            bar_label_numeric = start_time.tm_year;
        }
        // snap label to same alignment of histogram bars
        bar_label_numeric -= (bar_label_numeric % bar_time_value);
    }
    // create bar lables so an appropriate font size can be selected
    std::vector<std::string> bar_labels;
    std::vector<rgb_t> bar_label_colors;
    // if bars are thinner than 10pt, thin out the bar labels appropriately
    int label_every_n_bars = ((int) (10.0 / bar_allocation)) + 1;
    unsigned label_bars_offset = 0;
    // find the offset that will cause the '00' label to appear
    if(distinct_label_count > 0) {
        label_bars_offset = ((distinct_label_count - bar_label_numeric) %
                (bar_time_value * label_every_n_bars)) / bar_time_value;
    }
    bar_label_numeric += (label_bars_offset * bar_time_value);
    double widest_bar_label = 0;
    double tallest_bar_label = 0;
    cairo_set_font_size(cr, bar_label_font_size);
    for(size_t ii = 0; ii < bars; ii++) {
        if(ii % label_every_n_bars != label_bars_offset) {
            continue;
        }
        rgb_t bar_label_color;
        std::string bar_label = next_bar_label(bar_time_unit, bar_label_numeric,
                bar_time_value * label_every_n_bars, bar_label_color);
        cairo_text_extents_t label_extents;
        cairo_text_extents(cr, bar_label.c_str(), &label_extents);
        if(label_extents.width > widest_bar_label) {
            widest_bar_label = label_extents.width;
        }
        if(label_extents.height > tallest_bar_label) {
            tallest_bar_label = label_extents.height;
        }
        // add to list for later rendering
        bar_labels.push_back(bar_label);
        bar_label_colors.push_back(bar_label_color);
    }
    // don't let labels be wider than bars
    double safe_bar_label_font_size = bar_label_font_size;
    double bar_label_descent = tallest_bar_label * 1.75;
    double target_width = bar_width * bar_label_width_factor;
    if(widest_bar_label > target_width) {
        double factor = target_width / widest_bar_label;
        safe_bar_label_font_size *= factor;
        bar_label_descent *= factor;
    }
    // if we're skipping bars for labelling, increase the label size appropriately
    double label_size_multiplier = pow(1.2, (double) (label_every_n_bars - 1));
    safe_bar_label_font_size *= label_size_multiplier;
    bar_label_descent *= label_size_multiplier;


    // CDF and bar labels
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

        // draw bar label
        if(bar_time_unit.length() > 0 && bar_time_remainder == 0 &&
                ii % label_every_n_bars == label_bars_offset) {
            std::string label = bar_labels.at(ii / label_every_n_bars);
            rgb_t color = bar_label_colors.at(ii / label_every_n_bars);
            cairo_set_font_size(cr, safe_bar_label_font_size);
            cairo_set_source_rgb(cr, color.r, color.g, color.b);
            cairo_text_extents_t label_extents;
            cairo_text_extents(cr, label.c_str(), &label_extents);
            double label_x = x + ((bar_allocation - label_extents.width) / 2.0);
            double label_y = bounds.y + bounds.height + bar_label_descent;
            cairo_move_to(cr, label_x, label_y);
            cairo_show_text(cr, label.c_str());

            // move back to appropriate place for next CDF step
            cairo_move_to(cr, next_x, y);
        }
    }
    cairo_set_source_rgb(cr, cdf_color.r, cdf_color.g, cdf_color.b);
    cairo_set_line_width(cr, cdf_line_width);
    cairo_stroke(cr);
}

// create a new bar label based on numeric_label, then increment numeric_label
// by delta example: when invoked with ("day", 0, 2), "S" for sunday is
// returned and numeric_label is updated to 2 which will return "T" for tuesday
// next time
std::string time_histogram_view::next_bar_label(const std::string &unit, unsigned &numeric_label, unsigned delta,
        rgb_t &label_color)
{
    std::string output;
    if(numeric_label < delta) {
        label_color = bar_label_highlight_color;
    }
    else {
        label_color = bar_label_normal_color;
    }
    if(unit == SECOND_NAME || unit == MINUTE_NAME) {
        output = ssprintf("%02d", numeric_label);
        numeric_label = (numeric_label + delta) % 60;
    }
    else if(unit == HOUR_NAME) {
        output = ssprintf("%02d", numeric_label);
        numeric_label = (numeric_label + delta) % 24;
    }
    else if(unit == DAY_NAME) {
        label_color = bar_label_normal_color;
        switch(numeric_label) {
            case 6:
            case 0:
                label_color = bar_label_highlight_color;
                output = "S"; break;
            case 1:
                output = "M"; break;
            case 2:
                output = "T"; break;
            case 3:
                output = "W"; break;
            case 4:
                output = "R"; break;
            case 5:
                output = "F"; break;
        }
        numeric_label = (numeric_label + delta) % 7;
    }
    else if(unit == MONTH_NAME) {
        switch(numeric_label) {
            case 0:
                output = "Jan"; break;
            case 1:
                output = "Feb"; break;
            case 2:
                output = "Mar"; break;
            case 3:
                output = "Apr"; break;
            case 4:
                output = "May"; break;
            case 5:
                output = "Jun"; break;
            case 6:
                output = "Jul"; break;
            case 7:
                output = "Aug"; break;
            case 8:
                output = "Sep"; break;
            case 9:
                output = "Oct"; break;
            case 10:
                output = "Nov"; break;
            case 11:
                output = "Dec"; break;
        }
        numeric_label = (numeric_label + delta) % 12;
    }
    else if(unit == YEAR_NAME) {
        if(delta > 20) {
            output = ssprintf("%04d", numeric_label);
        }
        else {
            output = ssprintf("%02d", numeric_label % 100);
        }
        numeric_label = (numeric_label + delta);
    }
    return output;
}

std::vector<time_histogram_view::time_unit> time_histogram_view::build_time_units()
{
    std::vector<time_unit> output;

    output.push_back(time_unit(SECOND_NAME, 1L));
    output.push_back(time_unit(MINUTE_NAME, 60L));
    output.push_back(time_unit(HOUR_NAME, 60L * 60L));
    output.push_back(time_unit(DAY_NAME, 60L * 60L * 24L));
    output.push_back(time_unit(WEEK_NAME, 60L * 60L * 24L * 7L));
    output.push_back(time_unit(MONTH_NAME, 60L * 60L * 24L * 30L));
    output.push_back(time_unit(YEAR_NAME, 60L * 60L * 24L * 360L));

    return output;
}

std::vector<time_histogram_view::si_prefix> time_histogram_view::build_si_prefixes()
{
    std::vector<si_prefix> output;

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

    // The loop below is a bit confusing
    for(time_histogram::bucket::counts_t::const_iterator it = bucket.counts.begin(); it != bucket.counts.end();) {

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
            /* This gets after every bar except the last bar */
            colormap_t::const_iterator color_pair = color_map.find(it->first);
            if(color_pair != color_map.end()) {
                next_color = color_pair->second;
            }

            if(color == next_color) {
                height_accumulator += height;
                continue;
            }
        }

        /* this gets run after every bar */
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
