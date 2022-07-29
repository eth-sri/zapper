import numpy as np
import json
import pandas as pd

import sri_plot_helper as sph
import matplotlib.ticker as ticker

from run_microbench import base_params, line_params

FONT_SIZE = 8
COLOR_BAR = "#4b6094"
COLOR_ESTIMATE = "#de425b"

sph.configure_plots("ACM", FONT_SIZE)
np.set_printoptions(suppress=True)  # no scientific notation


def load_data():
    v_height = []
    v_records = []
    v_fresh = []
    v_payload = []
    v_registers = []
    v_cycles = []
    v_constraints = []
    line_data = []

    with open("grid-results.log", "r") as f:
        for line in f:
            data = json.loads(line)
            v_height.append(data["tree_height"])
            v_records.append(data["nof_tx_records"])
            v_fresh.append(data["nof_fresh"])
            v_payload.append(data["nof_record_payload_elements"])
            v_registers.append(data["nof_processor_registers"])
            v_cycles.append(data["nof_processor_cycles"])
            v_constraints.append(data["constraints"])
    
    with open("line-results.log", "r") as f:
        for line in f:
            data = json.loads(line)
            line_data.append(data)

    v_height = np.array(v_height)
    v_records = np.array(v_records)
    v_fresh = np.array(v_fresh)
    v_payload = np.array(v_payload)
    v_registers = np.array(v_registers)
    v_cycles = np.array(v_cycles)
    v_constraints = np.array(v_constraints)
    line_data = pd.DataFrame(line_data)

    return line_data, (v_height, v_records, v_fresh, v_payload, v_registers, v_cycles, v_constraints)


def get_factors_for_least_squares_fit(v_height, v_records, v_fresh, v_payload, v_registers, v_cycles):
    v_height_records = v_height * v_records
    v_payload_records = v_payload * v_records
    v_records_cycles = v_records * v_cycles
    v_payload_records_cycles = v_payload * v_records * v_cycles
    v_registers_cycles = v_registers * v_cycles
    v_fresh_cycles = v_fresh * v_cycles

    return np.vstack([np.ones(len(v_height)), v_fresh, v_records, v_height_records, v_payload_records, v_cycles, v_records_cycles, v_registers_cycles, v_fresh_cycles, v_payload_records_cycles]).transpose()


def least_squares_fit(v_height, v_records, v_fresh, v_payload, v_registers, v_cycles, v_constraints):
    A = get_factors_for_least_squares_fit(v_height, v_records, v_fresh, v_payload, v_registers, v_cycles)

    coeff, _, _, _ = np.linalg.lstsq(A, v_constraints, rcond=None)
    print(coeff)

    # print(v_constraints)
    # print(A.dot(coeff))
    print(np.max(np.abs((v_constraints - A.dot(coeff)) / v_constraints * 100)))

    return coeff


def plot_one_dim_params(line_data, ls_fit_coeff):

    def get_one_dim(data, dim_name):
        filtered = data
        for this_dim in base_params:
            if this_dim != dim_name:
                target = base_params[this_dim]
                filtered = filtered[filtered[this_dim] == target]
        return filtered
    
    labels = {
        "nof_tx_records": "$N_\\text{obj}$",
        "nof_fresh": "$N_\\text{fresh}$",
        "nof_processor_cycles": "$N_\\text{cycles}$",
        "tree_height": "$N_\\text{height}$",
        "nof_processor_registers": "$N_\\text{regs}$",
        "nof_record_payload_elements": "$N_\\text{fields}$",
    }
    fig, axes = sph.subplots(2, 3, figsize=(4.5, 5), bottom_spine=True)
    fig.subplots_adjust(wspace=0.1, hspace=0.9)

    for i, dim in enumerate(labels):
        ax = axes[i // 3][i % 3]

        this_data = get_one_dim(line_data, dim)
        min_x = line_params[dim][0]
        low = min_x - base_params[dim]*0.15
        max_x = line_params[dim][-1]
        high = max_x + base_params[dim]*0.15

        fit_data = []
        for other_dim in base_params:
            if other_dim == dim:
                fit_data.append(np.array([low, high]))
            else:
                fit_data.append(np.array([base_params[other_dim], base_params[other_dim]]))
        A = get_factors_for_least_squares_fit(fit_data[0], fit_data[1], fit_data[2], fit_data[3], fit_data[4], fit_data[5])
        predicted = A.dot(ls_fit_coeff)

        # bar
        bar_width = (this_data[dim].max() - this_data[dim].min()) / 7
        ax.bar(this_data[dim], this_data["constraints"], width=bar_width, color=COLOR_BAR)

        # dashed line
        line_style = (0, (1, 0.8))  # (0, length of printed, length of gap)
        ax.plot(np.array([low, high]), predicted, color=COLOR_ESTIMATE, linestyle=line_style, linewidth=1.5)

        ax.set_xticks(this_data[dim])
        ax.set_xlabel(labels[dim], labelpad=2)
        ax.xaxis.set_tick_params(length=3, pad=2, which='major')

        ax.set_ylim(0, 2.75e6)
        ax.set_yticks([0e6, 1e6, 2e6])
        ax.set_yticklabels([r'$0${}$\cdot${}$10^6$', r'$1${}$\cdot${}$10^6$', r'$2${}$\cdot${}$10^6$'])
        ax.set_yticks([5e5, 15e5, 25e5], minor=True)

        if i % 3 == 0:
            ax.set_ylabel("\# constraints")
        else:
            # ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.0e'))    # to remove axis multiplier label
            for tick in ax.yaxis.get_major_ticks() + ax.yaxis.get_minor_ticks():
                tick.tick1line.set_visible(False)
                tick.tick2line.set_visible(False)
                tick.label1.set_visible(False)
                tick.label2.set_visible(False)
        if i == 2:
            # ax.legend(
            #     ["estimate", "actual"],
            #     ncol=2,
            #     bbox_to_anchor=(0.4, 1.5),
            #     handlelength=1.1,
            #     columnspacing=1,
            #     handletextpad=0.6
            # )
            pass

        # place 3 ticks on x-axis
        ax.xaxis.set_ticks(np.array([min_x, (min_x + max_x) / 2, max_x]))

    sph.savefig("one-dim-params-plot.pdf", tight=False, bbox_inches='tight', pad_inches=0.01)


def print_ls_fit_formula(coeff):
    print("$\\numprint{{{:.0f}}} + \\numprint{{{:.0f}}}\\, \\constfresh + \\constobjs \\, (\\numprint{{{:.0f}}} + \\numprint{{{:.0f}}}\\, \\constheight + \\numprint{{{:.0f}}}\\, \\constpayload) + \\constcycles \\, (\\numprint{{{:.0f}}} + \\numprint{{{:.0f}}}\\, \\constobjs + \\numprint{{{:.0f}}}\\, \\constregisters + \\numprint{{{:.0f}}}\\, \\constfresh + \\numprint{{{:.0f}}}\\, \\constpayload \\, \\constobjs)$".format(*tuple(coeff)))


if __name__ == "__main__":
    line_data, grid_data = load_data()
    coeff = least_squares_fit(*grid_data)

    # use approximate coefficients
    coeff = np.array([3400, 130000, 160000, 3300, 1900, 1600, 76, 24, 120, 26])

    print_ls_fit_formula(coeff)
    plot_one_dim_params(line_data, coeff)
