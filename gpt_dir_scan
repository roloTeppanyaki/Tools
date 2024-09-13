# Define file types to search for and keywords to search within those files
$fileTypes = @("*.txt", "*.xml", "*.doc", "*.docx", "*.log")
$keywords = @("password", "passwd", "user")

# Function to scan directories recursively and process files
function Scan-Directory {
    param (
        [string]$Path
    )

    # Get all files of specified types in the directory and subdirectories
    foreach ($fileType in $fileTypes) {
        try {
            # Get the list of files
            $files = Get-ChildItem -Path $Path -Filter $fileType -Recurse -ErrorAction SilentlyContinue

            # Process each file
            foreach ($file in $files) {
                try {
                    # Check if the file is readable and open it
                    $content = Get-Content -Path $file.FullName -ErrorAction Stop

                    # Search for the keywords in the file content
                    foreach ($keyword in $keywords) {
                        if ($content -match $keyword) {
                            Write-Host "Keyword '$keyword' found in file: $($file.FullName)"
                        }
                    }
                } catch {
                    Write-Warning "Could not read file: $($file.FullName)"
                }
            }
        } catch {
            Write-Warning "Could not access directory: $Path"
        }
    }
}

# Get all available drives and start scanning
$drives = Get-PSDrive -PSProvider FileSystem
foreach ($drive in $drives) {
    Write-Host "Scanning drive: $($drive.Root)"
    Scan-Directory -Path $drive.Root
}
