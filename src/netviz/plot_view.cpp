/**
 * plot_view.cpp: 
 * Render titles, axes, and legends for various plots
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"                    // for ssprintf
#include "plot_view.h"

#ifdef HAVE_LIBCAIRO
#include <math.h>

const double plot_view::rgb_t::epsilon = 1.0 / 256.0;
const double plot_view::text_line_base_width = 0.05;
const double plot_view::span_arrow_angle = M_PI / 4.0;
const double plot_view::span_stop_angle = M_PI / 2.0;
const std::vector<std::string> plot_view::size_suffixes =
        plot_view::build_size_suffixes();

void plot_view::render(cairo_t *cr, const plot_view::bounds_t &bounds) {
    cairo_matrix_t original_matrix;
    cairo_get_matrix(cr, &original_matrix);

    // purple background for padding checking
    //cairo_set_source_rgb(cr, 0.50, 0.00, 0.50);
    //cairo_rectangle(cr, bounds.x, bounds.y, bounds.width, bounds.height);
    //cairo_fill(cr);

    double pad_left = width * pad_left_factor;
    double pad_top = height * pad_top_factor;
    double pad_bottom = height * pad_bottom_factor;
    double pad_right = width * pad_right_factor;

    // compute bounds for subclasses to render content into
    bounds_t content_bounds;

    content_bounds.x = bounds.x + pad_left;
    content_bounds.y = bounds.y + pad_top;
    content_bounds.width = bounds.width - pad_right - pad_left;
    content_bounds.height = bounds.height - pad_bottom - pad_top;

    cairo_text_extents_t title_extents;
    cairo_text_extents_t subtitle_extents;
    double font_size_title = title_font_size;

    cairo_translate(cr, bounds.x, bounds.y);

    double title_base_y = 0.0;
    if(title_on_bottom) {
        title_base_y = bounds.height - pad_bottom;
    }

    cairo_select_font_face(cr, "Sans",
               CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_size_title);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_text_extents(cr, title.c_str(), &title_extents);
    // Is the title too wide?
    double title_max_width = bounds.width * title_max_width_ratio;
    if(title_extents.width > title_max_width) {
        // scale the font size accordingly
        font_size_title *= title_max_width / title_extents.width;
        cairo_set_font_size(cr, font_size_title);
        cairo_text_extents(cr, title.c_str(), &title_extents);
    }
    // derive subtitle size and measure
    double font_size_subtitle = font_size_title *
        subtitle_font_size_factor;
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_text_extents(cr, subtitle.c_str(), &subtitle_extents);
    double intertitle_padding = subtitle_extents.height *
        subtitle_y_pad_factor;
    cairo_set_font_size(cr, font_size_title);
    double title_padded_height = title_extents.height *
        title_y_pad_factor;
    // render title text
    cairo_move_to(cr, (bounds.width - title_extents.width) / 2.0,
          title_base_y + title_extents.height +
          (title_padded_height - title_extents.height) / 2);
    cairo_show_text(cr, title.c_str());
    // render subtitle text
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_move_to(cr, (bounds.width - subtitle_extents.width) / 2.0,
          title_base_y + ((title_padded_height - title_extents.height) / 2) +
          title_extents.height + intertitle_padding +
          subtitle_extents.height);
    cairo_show_text(cr, subtitle.c_str());

    // render axis labels

    cairo_matrix_t unrotated_matrix;
    cairo_get_matrix(cr, &unrotated_matrix);
    cairo_text_extents_t axis_label_extents;
    cairo_set_font_size(cr, y_axis_font_size);
    cairo_text_extents(cr, y_label.c_str(), &axis_label_extents);
    double y_label_x = 0.0 + axis_label_extents.height;
    double y_label_centering_pad = ((content_bounds.height - axis_label_extents.width) / 2.0);
    double y_label_y = pad_top + y_label_centering_pad + axis_label_extents.width;
    cairo_move_to(cr, y_label_x, y_label_y);
    cairo_rotate(cr, -M_PI / 2.0);
    cairo_show_text(cr, y_label.c_str());
    cairo_set_matrix(cr, &unrotated_matrix);
    // add y axis decoration
    // TODO not implemented for brevity

    cairo_set_font_size(cr, x_axis_font_size);
    cairo_text_extents(cr, x_label.c_str(), &axis_label_extents);
    double x_label_centering_pad = (content_bounds.width - axis_label_extents.width) / 2.0;
    double x_label_x = pad_left + x_label_centering_pad;
    double x_label_y = bounds.height;
    cairo_move_to(cr, x_label_x, x_label_y);
    cairo_show_text(cr, x_label.c_str());

    // add x axis decoration
    if(x_axis_decoration == AXIS_SPAN_ARROW || x_axis_decoration == AXIS_SPAN_STOP) {
        double angle = span_arrow_angle;
        double line_width = x_axis_font_size * text_line_base_width;
        double tip_length = line_width * 10.0;
        if(x_axis_decoration == AXIS_SPAN_STOP) {
            angle = span_stop_angle;
            tip_length = line_width * 5.0;
        }
        double gap = line_width * 10.0;
        double x = x_label_x - gap;
        double y = x_label_y - axis_label_extents.height / 3.0;
        double pr_x, pr_y; // previous x and y positions
        // left of label
        cairo_move_to(cr, x, y);
        pr_x = x;
        pr_y = y;
        x = pr_x - (x_label_centering_pad - gap);
        y = pr_y;
        cairo_line_to(cr, x, y);
        pr_x = x;
        pr_y = y;
        x = pr_x + tip_length * sin(angle + M_PI / 2.0);
        y = pr_y + tip_length * cos(angle + M_PI / 2.0);
        cairo_line_to(cr, x, y);
        cairo_move_to(cr, pr_x, pr_y);
        x = pr_x + tip_length * sin(-angle + M_PI / 2.0);
        y = pr_y + tip_length * cos(-angle + M_PI / 2.0);
        cairo_line_to(cr, x, y);
        // right of label
        x = x_label_x + axis_label_extents.width + gap;
        y = x_label_y - axis_label_extents.height / 3.0;
        cairo_move_to(cr, x, y);
        pr_x = x;
        pr_y = y;
        x = pr_x + (x_label_centering_pad - gap);
        y = pr_y;
        cairo_line_to(cr, x, y);
        pr_x = x;
        pr_y = y;
        x = pr_x + tip_length * sin(angle - M_PI / 2.0);
        y = pr_y - tip_length * cos(angle - M_PI / 2.0);
        cairo_line_to(cr, x, y);
        cairo_move_to(cr, pr_x, pr_y);
        x = pr_x + tip_length * sin(-angle - M_PI / 2.0);
        y = pr_y - tip_length * cos(-angle - M_PI / 2.0);
        cairo_line_to(cr, x, y);
        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_set_line_width(cr, line_width);
        cairo_stroke(cr);
    }

    // render ticks

    double tick_length = bounds.width * tick_length_factor;
    double tick_width = bounds.height * tick_width_factor;

    // y ticks (packet counts)

    cairo_set_font_size(cr, y_tick_font_size);

    // translate down so the top of the window aligns with the top of
    // the graph itself
    cairo_translate(cr, 0, pad_top);

    double y_height = bounds.height - pad_bottom - pad_top;
    double y_tick_spacing = 0.0;
    if(y_tick_labels.size() > 1) {
        y_tick_spacing = y_height / (double) (y_tick_labels.size() - 1);
    }
    for(size_t ii = 0; ii < y_tick_labels.size(); ii++) {
        cairo_text_extents_t label_extents;
        double yy = y_height - (((double) ii) * y_tick_spacing);
        std::string label = y_tick_labels.at(ii);

        cairo_text_extents(cr, label.c_str(),
               &label_extents);
        cairo_move_to(cr, (pad_left - tick_length - label_extents.width),
          yy + (label_extents.height / 2));
        cairo_show_text(cr, label.c_str());

        // tick mark
        cairo_rectangle(cr, pad_left - tick_length, yy - (tick_width / 2),
                tick_length, tick_width);
        cairo_fill(cr);
    }

    // right ticks (packet counts)

    cairo_set_font_size(cr, right_tick_font_size);

    if(right_tick_labels.size() > 1) {
        y_tick_spacing = y_height / (double) (right_tick_labels.size() - 1);
    }
    for(size_t ii = 0; ii < right_tick_labels.size(); ii++) {
        cairo_text_extents_t label_extents;
        double yy = y_height - (((double) ii) * y_tick_spacing);
        std::string label = right_tick_labels.at(ii);

        cairo_text_extents(cr, label.c_str(),
               &label_extents);
        cairo_move_to(cr, (bounds.width - pad_right + tick_length),
          yy + (label_extents.height / 2));
        cairo_show_text(cr, label.c_str());

        // tick mark
        cairo_rectangle(cr, bounds.width - pad_right, yy - (tick_width / 2),
                tick_length, tick_width);
        cairo_fill(cr);
    }
    cairo_set_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    // x ticks (time)
    // TODO prevent overlap

    cairo_set_font_size(cr, x_tick_font_size);

    cairo_translate(cr, pad_left, bounds.height - pad_bottom);

    double x_width = bounds.width - (pad_right + pad_left);
    double x_tick_spacing = x_width / (x_tick_labels.size() - 1);

    for(size_t ii = 0; ii < x_tick_labels.size(); ii++) {
        cairo_text_extents_t label_extents;
        double xx = ii * x_tick_spacing;

        const char *label = x_tick_labels.at(ii).c_str();

        cairo_text_extents(cr, label, &label_extents);
        double pad = ((label_extents.height * x_tick_label_pad_factor) -
                label_extents.height) / 2;

        // prevent labels from running off the edge of the image
        double label_x = xx - (label_extents.width / 2.0);
        label_x = std::max(label_x, - pad_left);
        label_x = std::min(bounds.width - label_extents.width, label_x);

        cairo_move_to(cr, label_x, label_extents.height + pad);
        cairo_show_text(cr, label);
    }

    cairo_set_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    // render legend

    cairo_text_extents_t legend_label_extents;
    double chip_length = 0.0;

    // derive color chip size from largest label height
    for(size_t ii = 0; ii < legend.size(); ii++) {
        const legend_entry_t &entry = legend.at(ii);
        cairo_text_extents(cr, entry.label.c_str(), &legend_label_extents);

        chip_length = std::max(chip_length, legend_label_extents.height);
    }
    chip_length *= legend_chip_factor;

    cairo_translate(cr, bounds.width - (pad_right * 0.9),
        pad_top);

    cairo_set_font_size(cr, legend_font_size);

    for(size_t ii = 0; ii < legend.size(); ii++) {
        const legend_entry_t &entry = legend.at(ii);

        // chip
        cairo_set_source_rgb(cr, entry.color.r, entry.color.g,
             entry.color.b);
        cairo_rectangle(cr, 0, 0, chip_length, chip_length);
        cairo_fill(cr);

        // label
        cairo_set_source_rgb(cr, 0, 0, 0);
        cairo_text_extents(cr, entry.label.c_str(),
               &legend_label_extents);
        cairo_move_to(cr, chip_length * 1.2, (chip_length / 2.0) +
                (legend_label_extents.height / 2.0));
        cairo_show_text(cr, entry.label.c_str());

        // translate down for the next legend entry
        cairo_translate(cr, 0, chip_length);
    }

    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_set_matrix(cr, &original_matrix);

    // render axes and update content bounds
    double axis_width = bounds.height * axis_thickness_factor;

    cairo_rectangle(cr, content_bounds.x, content_bounds.y, axis_width,
            content_bounds.height);
    cairo_rectangle(cr, content_bounds.x,
            content_bounds.y + (content_bounds.height - axis_width),
            content_bounds.width, axis_width);
    // if there are right hand ticks, draw a right-hand axis
    if(right_tick_labels.size() > 0) {
        cairo_rectangle(cr, content_bounds.x + content_bounds.width - axis_width, content_bounds.y, axis_width,
                content_bounds.height);
    }
    cairo_fill(cr);

    content_bounds.x += axis_width;
    content_bounds.width -= axis_width;
    if(right_tick_labels.size() > 0) {
        content_bounds.width -= axis_width;
    }
    content_bounds.height -= axis_width;

    // render data!

    render_data(cr, content_bounds);
}

std::string plot_view::pretty_byte_total(uint64_t byte_count, uint8_t precision)
{
    //// packet count/size
    uint64_t size_log_1000 = (uint64_t) (log(byte_count) / log(1000));
    if(size_log_1000 >= size_suffixes.size()) {
        size_log_1000 = 0;
    }
    // only put decimal places if using a unit less granular than the byte (2.00 bytes looks silly)
    if(size_log_1000 == 0) {
        precision = 0;
    }
    return ssprintf("%.*f %sB", precision, (double) byte_count / pow(1000.0, (double) size_log_1000),
            size_suffixes.at(size_log_1000).c_str());
}

std::string plot_view::pretty_byte_total(uint64_t byte_count)
{
    return pretty_byte_total(byte_count, 2);
}

std::vector<std::string> plot_view::build_size_suffixes()
{
    std::vector<std::string> v;
    v.push_back("");
    v.push_back("K");
    v.push_back("M");
    v.push_back("G");
    v.push_back("T");
    v.push_back("P");
    v.push_back("E");
    return v;
}
#endif
