/**
 * count_histogram.cpp: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"

#include <algorithm>

#include "count_histogram.h"

void count_histogram::increment(std::string key, uint64_t delta)
{
    count_sum += delta;
    counts[key] += delta;
    top_list_dirty = true;
}

void count_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
    render(cr, bounds, get_top_list());
}

void count_histogram::render(cairo_t *cr, const plot::bounds_t &bounds,
        const std::vector<count_pair> &bars)
{
#ifdef CAIRO_PDF_AVAILABLE
    plot::ticks_t ticks;
    plot::legend_t legend;
    plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            bounds.height);
    //// have the plot class do labeling, axes, legend etc
    parent_plot.render(cr, bounds, ticks, legend, content_bounds);

    //// fill borders rendered by plot class
    render_bars(cr, content_bounds, bars);
#endif
}

void count_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds,
        const std::vector<count_pair> &count_list)
{
    if(count_list.size() < 1 || count_list.at(0).second < 1) {
        return;
    }
#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    cairo_set_source_rgb(cr, bar_color.r, bar_color.g, bar_color.b);

    double offset_unit = bounds.width / count_list.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
    uint64_t greatest = count_list.at(0).second;
    int index = 0;
    for(vector<count_pair>::const_iterator count = count_list.begin();
	count != count_list.end(); count++) {
	double bar_height = (((double) count->second) / ((double) greatest)) * bounds.height;

	if(bar_height > 0) {
	    cairo_rectangle(cr, index * offset_unit + space_width, bounds.height - bar_height,
			    bar_width, bar_height);
	    cairo_fill(cr);
	}
	index++;
    }

    cairo_set_matrix(cr, &original_matrix);
#endif
}

std::vector<count_histogram::count_pair> count_histogram::get_top_list()
{
    if(top_list_dirty) {
        build_top_list();
    }
    return top_list;
}

void count_histogram::set_top_list(std::vector<count_histogram::count_pair> new_list)
{
    top_list_dirty = false;
    top_list = new_list;
}

void count_histogram::build_top_list()
{
    top_list = std::vector<count_pair>(counts.begin(), counts.end());

    std::sort(top_list.begin(), top_list.end(), count_comparator());

    top_list.resize(max_bars);

    top_list_dirty = false;
}

bool count_histogram::count_comparator::operator()(const count_pair &a,
        const count_pair &b)
{
    if(a.second > b.second) {
        return true;
    }
    if(a.second < b.second) {
        return false;
    }
    return a.first > b.first;
}

uint64_t count_histogram::get_count_sum()
{
    return count_sum;
}
