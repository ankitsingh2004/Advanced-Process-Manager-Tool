def fcfs(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    for p in processes:
        start_time = max(current_time, p['arrival_time'])
        wait_time = start_time - p['arrival_time']
        turnaround_time = wait_time + p['burst_time']
        result.append((p['pid'], wait_time, turnaround_time))
        timeline.append((p['pid'], start_time, start_time + p['burst_time']))
        current_time = start_time + p['burst_time']
    return "FCFS", result, timeline

def sjf(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while processes or ready_queue:
        ready_queue.extend(p for p in processes if p['arrival_time'] <= current_time)
        processes = [p for p in processes if p['arrival_time'] > current_time]
        if ready_queue:
            current = min(ready_queue, key=lambda x: x['burst_time'])
            ready_queue.remove(current)
            start_time = current_time
            wait_time = start_time - current['arrival_time']
            turnaround_time = wait_time + current['burst_time']
            result.append((current['pid'], wait_time, turnaround_time))
            timeline.append((current['pid'], start_time, start_time + current['burst_time']))
            current_time += current['burst_time']
        else:
            current_time += 1
    return "SJF", result, timeline

def priority_scheduling(processes):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while processes or ready_queue:
        ready_queue.extend(p for p in processes if p['arrival_time'] <= current_time)
        processes = [p for p in processes if p['arrival_time'] > current_time]
        if ready_queue:
            current = min(ready_queue, key=lambda x: x['priority'])
            ready_queue.remove(current)
            start_time = current_time
            wait_time = start_time - current['arrival_time']
            turnaround_time = wait_time + current['burst_time']
            result.append((current['pid'], wait_time, turnaround_time))
            timeline.append((current['pid'], start_time, start_time + current['burst_time']))
            current_time += current['burst_time']
        else:
            current_time += 1
    return "Priority", result, timeline

def round_robin(processes, quantum=2):
    processes = sorted(processes, key=lambda x: x['arrival_time'])
    queue = [p.copy() for p in processes]
    for p in queue:
        p['remaining'] = p['burst_time']
    current_time = 0
    result = []
    timeline = []
    ready_queue = []
    while queue or ready_queue:
        ready_queue.extend(p for p in queue if p['arrival_time'] <= current_time)
        queue = [p for p in queue if p['arrival_time'] > current_time]
        if ready_queue:
            current = ready_queue.pop(0)
            run_time = min(quantum, current['remaining'])
            timeline.append((current['pid'], current_time, current_time + run_time))
            current['remaining'] -= run_time
            current_time += run_time
            if current['remaining'] == 0:
                wait_time = current_time - current['arrival_time'] - current['burst_time']
                turnaround_time = wait_time + current['burst_time']
                result.append((current['pid'], wait_time, turnaround_time))
            else:
                ready_queue.append(current)
        else:
            current_time += 1
    return "Round Robin", result, timeline

def get_processes_from_user():
    processes = []
    n = int(input("Enter the number of processes: "))
    for i in range(n):
        pid = input(f"PID of process {i+1}: ")
        arrival = int(input("Arrival time: "))
        burst = int(input("Burst time: "))
        priority = int(input("Priority (lower number = higher priority): "))
        processes.append({
            'pid': pid,
            'arrival_time': arrival,
            'burst_time': burst,
            'priority': priority
        })
    return processes

def print_results(name, result, timeline):
    print(f"\n{name} Scheduling Results:")
    print("PID | Wait Time | Turnaround Time")
    for pid, wait, turnaround in result:
        print(f"{pid} | {wait} | {turnaround}")
    print("\nExecution Timeline:")
    for pid, start, end in timeline:
        print(f"Process {pid} runs from {start} to {end}")

def main():
    print("CPU Scheduling Simulator")
    processes = get_processes_from_user()
    while True:
        print("\nSelect Algorithm:")
        print("1. FCFS")
        print("2. SJF")
        print("3. Priority")
        print("4. Round Robin")
        print("5. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            name, res, tl = fcfs(processes)
            print_results(name, res, tl)
        elif choice == "2":
            name, res, tl = sjf(processes)
            print_results(name, res, tl)
        elif choice == "3":
            name, res, tl = priority_scheduling(processes)
            print_results(name, res, tl)
        elif choice == "4":
            q = int(input("Time Quantum: "))
            name, res, tl = round_robin(processes, q)
            print_results(name, res, tl)
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
