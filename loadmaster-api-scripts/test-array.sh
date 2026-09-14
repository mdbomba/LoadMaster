#!/bin/bash

# Define the array with your structure
my_array=(
    "(SUBVS_APP1:{(CONTENT_RULE=SUBVS_APP1_MATCH), (REAL_SERVERS=(10.0.0.3, 10.0.0.4))}"
    "(SUBVS_APP2: {(CONTENT_RULE=SUBVS_APP2_MATCH), (REAL_SERVERS=(10.0.0.5, 10.0.0.6))}"
)

echo ''
echo ''
# To print the entire array
echo "All elements: ${my_array[@]}"
echo ''
# To iterate through the array
for app in "${my_array[@]}"; do
    echo ''
    echo "Processing: $app"
done
