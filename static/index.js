$(document).ready(function () {
    console.log("submit")
    // Unified form submission handler
    // Frontend JavaScript
    $('#query').on('click', function(event){
        alert("query");
        console.log("test")
        event.preventDefault();
        
        const filename = document.getElementById('filename').value;
        const otp = $('#otp').val().trim();
        console.log("filename", filename)
        console.log("otp", otp)
        const formData = new FormData();
        formData.append('filename', filename);
        formData.append('otp', otp);
        $.ajax({
            url: '/query_file',
            type: 'POST',
            contentType: 'application/json',
            data: formData,
            processData: false,
            contentType: false,
            success: function (data) {
                console.log("success")
                console.log(data)
                const fileList = document.getElementById('fileListContent');
                if (data.status === 'success') {
                    const file = data.file;

                    // Create a container for the file details
                    const fileDetails = document.createElement('div');
                    fileDetails.innerHTML = `
                        <h3>File Details</h3>
                        <p><strong>Filename:</strong> ${file.filename}</p>
                        <p><strong>Owner:</strong> ${file.owner}</p>
                        <p><strong>File Size:</strong> ${file.file_size} bytes</p>
                        <p><strong>File Content:</strong></p>
                        <pre>${file.file_content}</pre>
                    `;

                    // Append the details to the fileList container
                    fileList.appendChild(fileDetails);
                } else {
                    // Display an error message
                    const errorMessage = document.createElement('p');
                    errorMessage.style.color = 'red';
                    errorMessage.textContent = `Error: ${data.message}`;
                    fileList.appendChild(errorMessage);
                    }
                },
            error: function (xhr, status, error) {
                console.error('Error:', error);
                const fileList = document.getElementById('fileListContent');
                fileList.innerHTML = `
                    <div class="alert alert-danger mt-3">
                        Network error occurred
                    </div>`;
            }
        });
        
    });

});