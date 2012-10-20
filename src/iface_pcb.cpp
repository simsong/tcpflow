/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Jeremy Elson <jelson@circlemud.org>.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "iface_pcb.h"
#include "tcpflow.h"

// skip having a header for each in-tree plugin
pcb::callback_t timehistogram;

using std::vector;

namespace pcb
{
    pcb::callback_t *default_plugins[] = {
        timehistogram,
        0
    };

    pcap_handler wrapped;
    vector<pcb::callback_t *> plugins;
    bool passthrough;

    void init(pcap_handler const wrapped_, const bool passthrough_)
    {
        wrapped = wrapped_;
        plugins = vector<pcb::callback_t *>();
        passthrough = passthrough_;

        // load default plugins from array literal
        for(int ii = 0; default_plugins[ii]; ii++)
        {
            load_plugin(default_plugins[ii]);
        }
    }

    void load_plugin(const pcb::callback_t *new_plugin)
    {
        plugins.push_back(new_plugin);
    }

    void do_startup()
    {
        for(vector<pcb::callback_t *>::iterator plugin = plugins.begin();
                plugin != plugins.end(); plugin++)
        {
            (*plugin)(startup, NULL, NULL);
        }
    }

    void handle(u_char *user_args, const struct pcap_pkthdr *h,
            const u_char *p)
    {
        for(vector<pcb::callback_t *>::iterator plugin = plugins.begin();
                plugin != plugins.end(); plugin++)
        {
            (*plugin)(scan, h, p);
        }

        if(passthrough)
        {
            (wrapped)(user_args, h, p);
        }
    }

    void do_shutdown()
    {
        for(vector<pcb::callback_t *>::iterator plugin = plugins.begin();
                plugin != plugins.end(); plugin++)
        {
            (*plugin)(shutdown, NULL, NULL);
        }
    }
};
