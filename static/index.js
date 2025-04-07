$(document).ready(function () {
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
            data: formData,
            processData: false,
            contentType: false,  // 仅保留这一条，让 jQuery 自己设置合适的 multipart/form-data
            success: function (data) {
                console.log("success", data);
                const fileList = document.getElementById('fileListContent');
                fileList.innerHTML = ''; // Clear previous results
                if (data.status === 'success') {
                    // ...
                } else {
                    const errorMessage = document.createElement('p');
                    errorMessage.style.color = 'red';
                    errorMessage.textContent = `Error: ${data.message}`;
                    fileList.appendChild(errorMessage);
                }
            },
            error: function (xhr, status, error) {
                // 这里自动进入 error 回调，通常因为 HTTP 4xx/5xx
                let errMsg = "Network error occurred";
                try {
                    // 尝试解析后端返回的 JSON（如 {status: 'error', message: 'No permission...'}）
                    const response = JSON.parse(xhr.responseText);
                    if (response && response.message) {
                        errMsg = response.message;
                    }
                } catch (e) {
                }
        
                console.error('Error:', error);
                const fileList = document.getElementById('fileListContent');
                fileList.innerHTML = `
                    <div class="alert alert-danger mt-3">
                        ${errMsg}
                    </div>`;
            }
        });        
        
    });
});



// 示例：监听“share”按钮点击
$(document).on('click', '#share', function(e) {
    e.preventDefault();
    // filename从当前输入获取
    const filename = document.getElementById('filename').value.trim();

    // 弹出一个prompt让用户输入目标用户名
    const targetUser = prompt("Enter the username you want to share with:");
    if (!targetUser) {
        alert("No target user provided.");
        return;
    }

    const formData = new FormData();
    formData.append('filename', filename);
    formData.append('target_user', targetUser);

    fetch('/share_file', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            alert(data.message);  // “File 'xxx' shared to someUser”
        } else {
            alert(`Share error: ${data.message}`);
        }
    })
    .catch(err => {
        alert(`Failed to share file: ${err}`);
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