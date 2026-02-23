
#!/bin/bash

echo "Please select the step to execute:"
echo "1. cherry-pick and rename directories (btls* → boring*)"
echo "2. revert directory names (boring* → btls*)"
read -p "Enter step number (1/2): " step

branch_name="cherry-pick-upstream"

if [ "$step" = "1" ]; then
    if ! git remote | grep -q "^upstream$"; then
        read -p "No remote 'upstream' detected. Do you want to specify a custom remote URL? (Press Enter to use default: https://github.com/cloudflare/boring): " repo_url
        if [ -z "$repo_url" ]; then
            repo_url="https://github.com/cloudflare/boring"
        fi
        git remote add upstream "$repo_url"
        echo "Added upstream: $repo_url"
    fi

    if git show-ref --verify --quiet refs/heads/"$branch_name"; then
        read -p "Branch $branch_name already exists. Delete it? (y/n): " yn
        if [ "$yn" = "y" ]; then
            git branch -D "$branch_name"
            git checkout -b "$branch_name"
            echo "Branch deleted and recreated."
        else
            git checkout "$branch_name"
            echo "Switched to existing branch."
        fi
    else
        git checkout -b "$branch_name"
        echo "Branch created."
    fi

    rename_flag=0
    if [ ! -d "boring-sys" ]; then
        git mv btls-sys boring-sys
        rename_flag=1
    fi

    if [ ! -d "boring" ]; then
        git mv btls boring
        rename_flag=1
    fi

    if [ ! -d "tokio-boring" ]; then
        git mv tokio-btls tokio-boring
        rename_flag=1
    fi

    # Commit if any rename happened
    if [ "$rename_flag" = "1" ]; then
        git commit -am "merge"
    fi

    # Ask for cherry-pick reference (can be commit hash, branch, tag, etc.)
    read -p "Enter the reference(s) to cherry-pick (e.g. commit hash, upstream/branch, space separated): " cherry_ref
    if [ -z "$cherry_ref" ]; then
        echo "No reference entered, skipping cherry-pick."
    else
        git fetch upstream
        git cherry-pick upstream/$cherry_ref
    fi

elif [ "$step" = "2" ]; then
    # Step 2: revert directory names
    revert_flag=0
    if [ ! -d "btls-sys" ] && [ -d "boring-sys" ]; then
        git mv boring-sys btls-sys
        revert_flag=1
    fi

    if [ ! -d "btls" ] && [ -d "boring" ]; then
        git mv boring btls
        revert_flag=1
    fi

    if [ ! -d "tokio-btls" ] && [ -d "tokio-boring" ]; then
        git mv tokio-boring tokio-btls
        revert_flag=1
    fi

    if [ "$revert_flag" = "1" ]; then
        git commit -am "revert rename after merge"
        echo "Directory names reverted and committed."
    else
        echo "No revert needed, nothing to restore."
    fi
else
    echo "Invalid step number, exiting."
    exit 1
fi
