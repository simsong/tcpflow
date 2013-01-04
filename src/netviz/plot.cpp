/**
 * plot.cpp: 
 * Render titles, axes, and legends for various plots
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"

#include "plot.h"

void plot::render(cairo_t *cr, const plot::bounds_t &bounds,
        const plot::ticks_t &ticks, const plot::legend_t &legend,
        bounds_t &content_bounds) {
#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;
    cairo_get_matrix(cr, &original_matrix);

    double pad_bottom = height * pad_bottom_factor;
    double pad_right = width * pad_right_factor;

    cairo_text_extents_t title_extents;
    cairo_text_extents_t subtitle_extents;
    double font_size_title = title_font_size;

    cairo_translate(cr, bounds.x, bounds.y);

    cairo_select_font_face(cr, "Sans",
               CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_size_title);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_text_extents(cr, title, &title_extents);
    // Is the title too wide?
    double title_max_width = bounds.width * title_max_width_ratio;
    if(title_extents.width > title_max_width) {
        // scale the font size accordingly
        font_size_title *= title_max_width / title_extents.width;
        cairo_set_font_size(cr, font_size_title);
        cairo_text_extents(cr, title, &title_extents);
    }
    // derive subtitle size and measure
    double font_size_subtitle = font_size_title *
        subtitle_font_size_factor;
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_text_extents(cr, subtitle, &subtitle_extents);
    double intertitle_padding = subtitle_extents.height *
        subtitle_y_pad_factor;
    cairo_set_font_size(cr, font_size_title);
    double title_padded_height = title_extents.height *
        title_y_pad_factor;
    double titles_padded_height = title_padded_height +
        intertitle_padding + subtitle_extents.height;
    // render title text
    cairo_move_to(cr, (bounds.width - title_extents.width) / 2.0,
          title_extents.height +
          (title_padded_height - title_extents.height) / 2);
    cairo_show_text(cr, title);
    // render subtitle text
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_move_to(cr, (bounds.width - subtitle_extents.width) / 2.0,
          ((title_padded_height - title_extents.height) / 2) +
          title_extents.height + intertitle_padding +
          subtitle_extents.height);
    cairo_show_text(cr, subtitle);

    // render ticks

    double tick_length = bounds.width * tick_length_factor;
    double tick_width = bounds.height * tick_width_factor;

    // y ticks (packet counts)

    // find longest label and pad for it
    cairo_text_extents_t label_extents;
    cairo_set_font_size(cr, y_tick_font_size);
    double max_label_width = 0.0;
    for(size_t ii = 0; ii < ticks.y_labels.size(); ii++) {
        cairo_text_extents(cr, ticks.y_labels.at(ii).c_str(),
               &label_extents);
        if(label_extents.width > max_label_width) {
            max_label_width = label_extents.width;
        }
    }
    double y_label_allotment = max_label_width *
        y_tick_label_pad_factor;
    double left_padding = y_label_allotment + tick_length;

    // translate down so the top of the window aligns with the top of
    // the graph itself
    cairo_translate(cr, 0, titles_padded_height);

    double y_height = bounds.height - pad_bottom - titles_padded_height;
    double y_tick_spacing = y_height / (double) (ticks.y_labels.size() - 1);
    for(size_t ii = 0; ii < ticks.y_labels.size(); ii++) {
        double yy = (((double) ii) * y_tick_spacing);

        cairo_text_extents(cr, ticks.y_labels.at(ii).c_str(),
               &label_extents);
        cairo_move_to(cr, (y_label_allotment - label_extents.width) / 2,
          yy + (label_extents.height / 2));
        cairo_show_text(cr, ticks.y_labels.at(ii).c_str());

        // tick mark
        cairo_rectangle(cr, y_label_allotment, yy - (tick_width / 2),
                tick_length, tick_width);
        cairo_fill(cr);
    }
    cairo_set_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    // x ticks (time)
    // TODO prevent overlap

    cairo_set_font_size(cr, x_tick_font_size);

    cairo_translate(cr, left_padding, bounds.height - pad_bottom);

    double x_width = bounds.width - (pad_right + left_padding);
    double x_tick_spacing = x_width / (ticks.x_labels.size() - 1);

    for(size_t ii = 0; ii < ticks.x_labels.size(); ii++) {
        double xx = ii * x_tick_spacing;

        const char *label = ticks.x_labels.at(ii).c_str();

        cairo_text_extents(cr, label, &label_extents);
        double pad = ((label_extents.height * x_tick_label_pad_factor) -
                label_extents.height) / 2;

        // prevent labels from running off the edge of the image
        double label_x = xx - (label_extents.width / 2.0);
        label_x = max(label_x, -left_padding);
        label_x = min(bounds.width - label_extents.width, label_x);

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

        chip_length = max(chip_length, legend_label_extents.height);
    }
    chip_length *= legend_chip_factor;

    cairo_translate(cr, bounds.width - (pad_right * 0.9),
        titles_padded_height);

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

    // compute bounds for calling class to render content into
    content_bounds.x = bounds.x + left_padding;
    content_bounds.y = bounds.y + titles_padded_height;
    content_bounds.width = bounds.width - pad_right - left_padding;
    content_bounds.height = bounds.height - pad_bottom - titles_padded_height;

    // render axes and update content bounds
    double axis_width = bounds.height * axis_thickness_factor;

    cairo_rectangle(cr, content_bounds.x, content_bounds.y, axis_width,
            content_bounds.height);
    cairo_rectangle(cr, content_bounds.x,
            content_bounds.y + (content_bounds.height - axis_width),
            content_bounds.width, axis_width);
    cairo_fill(cr);

    content_bounds.x += axis_width;
    content_bounds.width -= axis_width;
    content_bounds.height -= axis_width;
#endif
}

