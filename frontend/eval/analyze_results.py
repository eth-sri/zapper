import os
import json
import pandas as pd
import glob
import re
import sri_plot_helper as sph
import math

pd.set_option('display.max_columns', None)

FONT_SIZE = 8
COLOR_BARS = [  # generated using https://learnui.design/tools/data-color-picker.html#palette
"#4b6094",
"#8569a2",
"#b972a2",
"#e28098",
"#fc9889",
"#ffb77e",
"#ffdb80",
]

sph.configure_plots("ACM", FONT_SIZE)

def read_data(run_name):
    inst_data = []
    tx_time_data = []
    setup_total_time = None
    setup_gm17_time = None
    compile_time_data = []
    proof_gen_times = []
    verify_check_proof_times = {}
    verify_insert_merkle_times = {}
    const_data = []
    meta_data = {}
    config = {}
    with open(os.path.join("results", run_name, run_name + "_backend_data.log")) as f:
        for line in f:
            data = json.loads(line)
            if "constraints" in data:
                const_data.append(data["constraints"])
            elif "config" in data:
                config = data["config"]
            elif "time" in data and data["time"]["key"] == "generate_proof":
                proof_gen_times.append(data["time"]["elapsed_sec"])
            elif "time" in data and data["time"]["key"] == "gm17_setup":
                setup_gm17_time = data["time"]["elapsed_sec"]
    
    tx_idx = 0
    with open(os.path.join("results", run_name, run_name + "_data.log")) as f:
        for line in f:
            data = json.loads(line)
            if "nof_instructions" in data["data"]:
                inst_data.append({"class": data["context"][1], "fun": data["context"][2], "instructions": data["data"]["nof_instructions"]})
            elif "time" in data["data"]:
                if data["data"]["time"]["key"] == "setup":
                    setup_total_time = data["data"]["time"]["elapsed_sec"]
                elif data["data"]["time"]["key"] == "compile":
                    compile_time_data.append({"app": data["context"][0], "time_sec": data["data"]["time"]["elapsed_sec"]})
                elif data["data"]["time"]["key"] == "execute":
                    tx_time_data.append({"class": data["context"][1],
                                         "fun": data["context"][2],
                                         "type": "execute",
                                         "time_sec": data["data"]["time"]["elapsed_sec"],
                                         "proof_gen_time_sec": proof_gen_times[tx_idx]})
                    tx_idx += 1
                elif data["data"]["time"]["key"] == "verify_check_proof":
                    verify_check_proof_times[(data["context"][1], data["context"][2])] = data["data"]["time"]["elapsed_sec"]
                elif data["data"]["time"]["key"] == "verify_insert_merkle":
                    verify_insert_merkle_times[(data["context"][1], data["context"][2])] = data["data"]["time"]["elapsed_sec"]
                elif data["data"]["time"]["key"] == "verify":
                    tx_time_data.append({"class": data["context"][1],
                                         "fun": data["context"][2],
                                         "type": "verify",
                                         "time_sec": data["data"]["time"]["elapsed_sec"],
                                         "verify_merkle_sec": verify_insert_merkle_times[(data["context"][1], data["context"][2])],
                                         "verify_proof_sec": verify_check_proof_times[(data["context"][1], data["context"][2])]})

    for file_name in glob.iglob("scenarios/*"):
        if "__" not in file_name:
            scenario_module = "eval.scenarios." + file_name.split("/")[1].split(".")[0]
            meta_data[scenario_module] = {"classes": []}
            with open(file_name) as f:
                for line in f:
                    obj = re.match(r"^# META-([A-Z]+)( (.*))?$", line)
                    if obj is not None:
                        g = obj.groups()
                        meta_data[scenario_module][g[0]] = g[2]
                    obj = re.match(r"^class ([A-Za-z]+)\(Contract\):$", line)
                    if obj is not None:
                        g = obj.groups()
                        meta_data[scenario_module]["classes"].append(g[0])

    const_data = pd.DataFrame(const_data)
    inst_data = pd.DataFrame(inst_data)
    tx_time_data = pd.DataFrame(tx_time_data)
    compile_time_data = pd.DataFrame(compile_time_data)
    return inst_data, (setup_total_time, setup_gm17_time, compile_time_data, tx_time_data), const_data, meta_data, config


def generate_app_table(inst_data, meta_data):
    classes_using_coin = ["Auction", "DexOffer", "Wallet", "Ticket"]
    additional_info = {"Coin": " (\\cref{fig:coin-dex-code})", "DexOffer": " (\\cref{fig:coin-dex-code})"}

    nof_total_classes = 0
    app_rows = []
    for module in meta_data:
        data = meta_data[module]
        nof_classes = len(data["classes"])
        for i in range(0, nof_classes):
            class_name = data["classes"][i]
            data_for_class = inst_data[inst_data["class"] == module + "." + class_name]
            nof_functions = len(data_for_class.index)
            max_instructions = data_for_class["instructions"].max()
            min_instructions = data_for_class["instructions"].min()
            instructions_str = str(max_instructions) if max_instructions == min_instructions else str(min_instructions) + "--" + str(max_instructions)

            class_display_name = class_name
            if class_name in classes_using_coin:
                class_display_name = class_display_name + "\\textsuperscript{\\textdollar{}}"
            if class_name in additional_info:
                class_display_name = class_display_name + additional_info[class_name]

            nof_total_classes += 1

            if i == 0:
                row = "\\multirow{%i}{1cm}{%s} & \\multirow{%i}{=}{%s} & %s & %i (%s) \\\\" % (nof_classes, data["NAME"], nof_classes, data["DESC"], class_display_name, nof_functions, instructions_str)
            else:
                row = row + "                 & & %s & %i (%s) \\\\" % (class_display_name, nof_functions, instructions_str)
            if i == nof_classes-1:
                row = row + "\\midrule"
        app_rows.append((data["NAME"], row))

    app_rows.sort()
    print("%")
    for row in app_rows:
        print(row[1])
    print("%")

    print("%")
    print("\\newcommand{\\evalnofapps}{%i\\xspace}" % (len(app_rows)))
    print("\\newcommand{\\evalnofclasses}{%i\\xspace}" % (nof_total_classes))
    print("%")

def print_config(config):
    print("%")
    print("\\newcommand{\\evalconsttreeheight}{%i\\xspace}" % (config["TREE_HEIGHT"]))
    print("\\newcommand{\\evalconstobjs}{%i\\xspace}" % (config["NOF_TX_RECORDS"]))
    print("\\newcommand{\\evalconstfresh}{%i\\xspace}" % (config["NOF_TX_FRESH"]))
    print("\\newcommand{\\evalconstcycles}{%i\\xspace}" % (config["NOF_PROCESSOR_CYCLES"]))
    print("\\newcommand{\\evalconstregisters}{%i\\xspace}" % (config["NOF_PROCESSOR_REGISTERS"]))
    print("\\newcommand{\\evalconstpayload}{%i\\xspace}" % (config["NOF_RECORD_PAYLOAD_ELEMENTS"]))
    print("%")

def generate_circuit_components_plot(const_data):
    const_data = const_data.groupby(['part']).sum()
    total_constraints = const_data.loc["main_circuit"][0]
    const_data_reduced = const_data.drop("access_input").drop("access_output").drop("run_processor")\
        .drop("processor_state_matching").drop("derive_owner_public_key").drop("main_circuit")\
        .drop("authenticate_sender").drop("check_record_decryption").drop("check_record_encryption")
    bulk = const_data_reduced.sum()
    const_data_reduced.loc["other"] = total_constraints - bulk
    const_data_reduced = const_data_reduced.sort_values(by=["num_constraints"], ascending=False)

    fig, axes = sph.subplots(1, 1, figsize=(1.2, 6), nice_grid='y', bottom_spine=True)

    labels = {
        "verify_membership_merkle_tree": "Merkle tree",
        "derive_fresh_values": "\\noindent fresh values,\\\\[-0.5em]$\\mathit{oid}$, $\\text{sk}_\\mathit{oid}$",
        "processor_gadget": "processor",
        "derive_sn": "\\noindent derive $\\mathit{sn}$",
        "derive_sn_nonce": "\\noindent derive $\\rho^\\text{out}$",
        "derive_sn_nonce_dummy": "\\noindent derive $\\rho^\\text{in}$",
        "other": "(other)"
    }

    bottom = 0
    for i, y in enumerate(const_data_reduced["num_constraints"]):
        axes.bar(0, y, 0.7, bottom=bottom, color=COLOR_BARS[i])
        center = bottom + y/2.1
        axes.text(0.6, center, labels[const_data_reduced.index[i]], verticalalignment="center")
        if i != len(labels)-1:
            axes.text(0, center, "{:.0f}\%".format(y / total_constraints * 100), verticalalignment="center", horizontalalignment="center")
        bottom += y
    axes.grid(visible=True, which='major', axis="y", color='w')
    axes.set_xticks([])
    axes.set_ylabel("\# constraints")
    axes.set_xlim(-0.5, 0.5)
    fig.subplots_adjust(top=.95)

    sph.savefig("circuit-components-plot.pdf", tight=False, pad_inches=0.02,  bbox_inches='tight')

    print("%")
    print("\\newcommand{{\\evaltotalconstraints}}{{${:.2f}{{\cdot}}10^6$\\xspace}}".format(total_constraints / 1e6))
    print("%")


def generate_timing_table(time_data):
    setup_total_time, setup_gm17_time, compile_time, tx_time = time_data

    execute_time = tx_time[tx_time["type"] == "execute"]
    execute_time = execute_time.assign(proof_gen_fraction=lambda df: df.proof_gen_time_sec / df.time_sec)
    verify_time = tx_time[tx_time["type"] == "verify"]
    verify_time = verify_time.assign(merkle_fraction=lambda df: df.verify_merkle_sec / df.time_sec).assign(proof_fraction=lambda df: df.verify_proof_sec / df.time_sec)

    print("%")
    print("\\newcommand{{\\abstracttimecreate}}{{{:.0f}}}".format(math.ceil(execute_time["time_sec"].max())))
    print("\\newcommand{{\\abstracttimeverify}}{{{:.2f}}}".format(math.ceil(verify_time["time_sec"].max() * 100) / 100))
    print("%")

    print("%")
    print("\\newcommand{{\\evalproofgenpercent}}{{{:.2f}\\%\\xspace}}".format(execute_time["proof_gen_fraction"].mean() * 100))
    print("\\newcommand{{\\evalmerklepercent}}{{{:.1f}\\%\\xspace}}".format(verify_time["merkle_fraction"].mean() * 100))
    print("\\newcommand{{\\evalverifypercent}}{{{:.1f}\\%\\xspace}}".format(verify_time["proof_fraction"].mean() * 100))
    print("\\newcommand{{\\evaltrustedsetuppercent}}{{{:.2f}\\%\\xspace}}".format(setup_gm17_time / setup_total_time * 100))
    print("%")

    print("%")
    print("one-time & setup & {:.3f}~s & \\\\ \\midrule".format(setup_total_time))
    print("per app & compile & {:.3f}~s & ($\\pm${:.3f}~s) \\\\ \\midrule".format(compile_time["time_sec"].mean(), compile_time["time_sec"].std()))
    print("\multirow{{2}}{{1.2cm}}{{per tx}} & create & {:.3f}~s & ($\\pm${:.3f}~s) \\\\".format(execute_time["time_sec"].mean(), execute_time["time_sec"].std()))
    print("& verify & {:.3f}~s & ($\\pm${:.3f}~s) \\\\ \\midrule".format(verify_time["time_sec"].mean(), verify_time["time_sec"].std()))
    print("%")


def print_tx_size(config):
    # compute transaction size in bytes, assuming called function and class are identified by a 32-bit (4 bytes) integer each
    #
    # Tx size (bytes):
    #    class_id            4
    #    function_id         4
    #    merkle_tree_root    32
    #    consumed_serials    32 * NOF_TX_RECORDS
    #    new_records         673 * NOF_TX_RECORDS
    #    proof               388
    #    unique_seed         32
    #    current_time        32
    tx_bytes = 4 + 4 + 32*3 + 32*config["NOF_TX_RECORDS"] + 673*config["NOF_TX_RECORDS"] + 388
    print("%")
    print("\\newcommand{{\\evaltxsizebytes}}{{{:.0f}}}".format(tx_bytes))
    print("%")


if __name__ == "__main__":
    inst_data, time_data, const_data, meta_data, config = read_data("reference")
    generate_app_table(inst_data, meta_data)
    print_config(config)
    generate_circuit_components_plot(const_data)
    generate_timing_table(time_data)
    print_tx_size(config)
