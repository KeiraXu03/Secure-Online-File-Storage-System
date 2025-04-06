$(document).ready(function () {
    // Unified form submission handler
    // Frontend JavaScript
    $('#query').on('click', function(event){
        event.preventDefault();
        
        const filename = document.getElementById('filename').value;
        const otp = $('#otp').val().trim();
        const secret_key = $('#secret_key').val().trim();
        const formData = new FormData();
        formData.append('filename', filename);
        formData.append('otp', otp);
        formData.append('private_key', secret_key);
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
                fileList.innerHTML = ''; // Clear previous results
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
                        <pre id="txt_content">${file.file_content}</pre>
                        <div class="row">
                            <div class="col-3">
                                <button id="downloadBtn" class="btn btn-primary" onclick="downloadFile('${file.filename}')">download</button>
                            </div>
                            <div class="col-3">
                                <button id="edit" class="btn btn-primary">edit</button>
                            </div>
                            <div class="col-3">
                                <button id="share" class="btn btn-primary">share</button>
                            </div>
                            <div class="col-3">
                                <button id="query" class="btn btn-primary" onclick="deleteFile('${file.filename}')">delete</button>
                            </div>
                        <div>
                        
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

function downloadFile(filename) {
    // 获取 <pre> 标签中的内容
    const fileContent = document.getElementById('txt_content').textContent;

    // 创建一个 Blob 对象，表示文件内容
    const blob = new Blob([fileContent], { type: 'text/plain' });

    // 创建一个下载链接
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    console.log(filename)
    // 设置下载的文件名（确保以 .txt 结尾）
    const filename2 = filename.endsWith('.txt') ? filename : `${filename}.txt`;
    link.download = filename2;

    // 触发下载
    link.click();

    // 释放 URL 对象资源
    URL.revokeObjectURL(link.href);
}
function deleteFile(fileid) {
    const formData = new FormData();
    formData.append('username', "test");
    // 使用 jQuery AJAX 发送 DELETE 请求
    $.ajax({
        url: `/delete_file/${fileid}`, // 后端 API 路径
        method: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function (response) {
            alert(response.message);
            // 更新前端 UI：移除文件列表中的文件
            $(`#file-${fileid}`).remove();
        },
        error: function (xhr) {
            const error = xhr.responseJSON;
            alert(`Error: ${error.error || 'Failed to delete file'}`);
        }
    });
}