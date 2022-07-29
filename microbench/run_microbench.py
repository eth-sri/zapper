import os
import shutil
import subprocess

base_params = {
    "tree_height": 32,
    "nof_tx_records": 4,
    "nof_fresh": 4,
    "nof_record_payload_elements": 9,
    "nof_processor_registers": 10,
    "nof_processor_cycles": 100
}

grid_params = {
    "tree_height": [16, 32, 48],
    "nof_tx_records": [2, 5, 8],
    "nof_fresh": [2, 5, 8],
    "nof_record_payload_elements": [6, 9, 12],
    "nof_processor_registers": [6, 9, 12],
    "nof_processor_cycles": [50, 100, 150]
}

line_params = {
    "tree_height": [16, 24, 32, 40, 48],
    "nof_tx_records": [2, 3, 4, 5, 6],
    "nof_fresh": [2, 3, 4, 5, 6],
    "nof_record_payload_elements": [3, 6, 9, 12, 15],
    "nof_processor_registers": [8, 10, 12, 14, 16],
    "nof_processor_cycles": [50, 100, 150, 200, 250]
}


def get_grid_dims():
    return [grid_params["tree_height"], grid_params["nof_tx_records"], grid_params["nof_fresh"], grid_params["nof_record_payload_elements"], grid_params["nof_processor_registers"], grid_params["nof_processor_cycles"]]


def get_line_dims():
    base = [base_params["tree_height"], base_params["nof_tx_records"], base_params["nof_fresh"], base_params["nof_record_payload_elements"], base_params["nof_processor_registers"], base_params["nof_processor_cycles"]]
    line = [line_params["tree_height"], line_params["nof_tx_records"], line_params["nof_fresh"], line_params["nof_record_payload_elements"], line_params["nof_processor_registers"], line_params["nof_processor_cycles"]]
    return base, line


def grid(dims, acc, f):
    if len(dims) == 0:
        f(acc)
        return
    vals = dims[0]
    for v in vals:
        acc.append(v)
        grid(dims[1:], acc, f)
        acc.pop()


def line(dims, f):
    base, line = dims
    f(base)
    for i in range(0, len(base)):
        vals = base.copy()
        for v in line[i]:
            if v != base[i]:
                vals[i] = v
                f(vals)


def run_config(values, template_contents, result_f):
    content = template_contents.replace("{{tree_height}}", str(values[0]))
    content = content.replace("{{nof_tx_records}}", str(values[1]))
    content = content.replace("{{nof_fresh}}", str(values[2]))
    content = content.replace("{{nof_record_payload_elements}}", str(values[3]))
    content = content.replace("{{nof_processor_registers}}", str(values[4]))
    content = content.replace("{{nof_processor_cycles}}", str(values[5]))
    with open(constants_file, "w") as f:
        f.write(content)

    subprocess.call(["cargo", "build", "--release"], cwd=os.path.join(os.getcwd(), "runner"))
    ret = subprocess.check_output([os.path.join(os.getcwd(), "runner", "target", "release", "microbench-runner")])
    constraints = int(ret.decode('utf-8').strip())

    info = f'{{"tree_height": {values[0]}, "nof_tx_records": {values[1]}, "nof_fresh": {values[2]}, "nof_record_payload_elements": {values[3]}, "nof_processor_registers": {values[4]}, "nof_processor_cycles": {values[5]}, "constraints": {constraints}}}'
    print(info)
    print(info, file=result_f)


if __name__ == "__main__":

    grid_results_file = "grid-results.log"
    line_results_file = "line-results.log"

    # prepare temporary copy of backend
    tmp_backend_dir = "tmp-backend"
    shutil.copytree("../backend/lib", os.path.join(tmp_backend_dir, "lib"))

    try:
        constants_file = os.path.join(tmp_backend_dir, "lib", "src", "constants.rs")
        template_contents = None
        with open("constants-template.rs", "r") as f:
            template_contents = f.read()
        
        # evaluate on grid (for least-squares fit)
        with open(grid_results_file, "w") as result_f:
            def run(values):
                run_config(values, template_contents, result_f)
            grid(get_grid_dims(), [], run)

        # evaluate on line (for plots)
        with open(line_results_file, "w") as result_f:
            def run(values):
                run_config(values, template_contents, result_f)
            line(get_line_dims(), run)


    finally:
        shutil.rmtree(tmp_backend_dir)
