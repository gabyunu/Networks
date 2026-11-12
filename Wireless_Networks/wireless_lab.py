import subprocess
import re
import numpy as np
import matplotlib.pyplot as plt

# Step 1: Run Ping Test

def run_ping(host="8.8.8.8", count=10):
    result = subprocess.run(
        ["ping", "-c", str(count), host],
        capture_output=True,
        text=True
    )
    return result.stdout

ping_output = run_ping()

print(ping_output)


# Step 2: Extract Latency Values

def extract_latencies(ping_text):
    times = re.findall(r'time=([\d.]+)', ping_text)
    return [float(t) for t in times]

latencies = extract_latencies(ping_output)

print("Latencies:", latencies)


# Step 3: Compute Metrics

lat_array = np.array(latencies)

if len(lat_array) < 2:
    raise RuntimeError("Not enough ping responses to calculate jitter.")

# Average latency
avg_latency = np.mean(lat_array)

# Standard deviation (stability)
std_latency = np.std(lat_array)

# Jitter
jitter = np.mean(np.abs(np.diff(lat_array)))

# Print results
print(f"Average Latency: {avg_latency:.2f} ms")
print(f"Stability (Std Dev): {std_latency:.2f} ms")
print(f"Jitter: {jitter:.2f} ms")


# Step 4: Plot Results

plt.figure(figsize=(10, 5))

plt.plot(
    range(1, len(lat_array) + 1),
    lat_array,
    marker='o',
    color='orange',
    label='Mobile Data'
)

plt.xlabel("Packet Number")
plt.ylabel("Latency (ms)")
plt.title("Mobile Data - Latency Over Time")

plt.xticks(range(1, len(lat_array) + 1))
plt.legend()
plt.grid(True)

# Save graph
plt.savefig("mobile_latency.png", dpi=300, bbox_inches="tight")

# Display graph
plt.show()


# Step 5: Save Mobile Data Results

with open("mobile_results.txt", "w") as file:
    file.write("MOBILE DATA RESULTS\n")
    file.write("====================\n\n")

    file.write(f"Average Latency: {avg_latency:.2f} ms\n")
    file.write(f"Standard Deviation: {std_latency:.2f} ms\n")
    file.write(f"Jitter: {jitter:.2f} ms\n")

    file.write("\nLatency Values:\n")
    file.write(str(latencies))

print("\nMobile data results saved successfully!")