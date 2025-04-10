$(document).ready(function () {
    // Unified form submission handler
    // Frontend JavaScript
    $('#query').on('click', async function(event) {
        event.preventDefault();
        const filename = $('#filename').val().trim();
        const otp = $('#otp').val().trim();
        const privateKeyPem = $('#secret_key').val().trim();  // 用户输入的私钥PEM
        if (!filename || !otp || !privateKeyPem) {
          alert("Please provide filename, OTP, and secret key");
          return;
        }
        const formData = new FormData();
        formData.append('filename', filename);
        formData.append('otp', otp);
        try {
          const res = await fetch('/query_file', { method: 'POST', body: formData });
          const data = await res.json();
          const fileList = document.getElementById('fileListContent');
          fileList.innerHTML = '';
          if (data.status === 'success') {
            // 导入私钥PEM成为CryptoKey对象
            const pemHeader = "-----BEGIN PRIVATE KEY-----";
            const pemFooter = "-----END PRIVATE KEY-----";
            const pemContents = privateKeyPem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, '');
            const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
            const privateKey = await window.crypto.subtle.importKey(
              "pkcs8",
              binaryDer.buffer,
              { name: "RSA-OAEP", hash: "SHA-256" },
              false,
              ["decrypt"]
            );
            // 解码Base64加密内容为字节数组并分块解密
            const encryptedContent = data.file.encrypted_content;
            const encryptedBytes = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
            const decryptedChunks = [];
            for (let i = 0; i < encryptedBytes.length; i += 256) {
              const chunk = encryptedBytes.slice(i, i + 256);
              const decryptedChunk = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, chunk);
              decryptedChunks.push(new Uint8Array(decryptedChunk));
            }
            // 合并解密后的块并转换为文本
            let totalLen = decryptedChunks.reduce((sum, arr) => sum + arr.length, 0);
            let decryptedData = new Uint8Array(totalLen);
            let offset = 0;
            for (const arr of decryptedChunks) {
              decryptedData.set(arr, offset);
              offset += arr.length;
            }
            const fileText = new TextDecoder().decode(decryptedData);
            // 动态构造文件详情界面
            const file = data.file;
            const fileDetails = document.createElement('div');
            // 根据权限显示不同操作按钮
            let buttonsHTML = '';
            if (data.is_owner) {
              buttonsHTML = `
                <div class="col-3"><button id="downloadBtn" class="btn btn-primary" onclick="downloadFile('${file.filename}')">download</button></div>
                <div class="col-3"><button id="edit" class="btn btn-primary">edit</button></div>
                <div class="col-3"><button id="share" class="btn btn-primary">share</button></div>
                <div class="col-3"><button id="deleteBtn" class="btn btn-primary" onclick="deleteFile('${file.filename}')">delete</button></div>
              `;
            } else {
              buttonsHTML = `
                <div class="col-3"><button id="downloadBtn" class="btn btn-primary" onclick="downloadFile('${file.filename}')">download</button></div>
              `;
            }
            fileDetails.innerHTML = `
              <h3>File Details</h3>
              <p><strong>Filename:</strong> ${file.filename}</p>
              <p><strong>Owner:</strong> ${file.owner}</p>
              <p><strong>File Size:</strong> ${file.file_size} bytes</p>
              <p><strong>File Content:</strong></p>
              <pre id="txt_content">${fileText}</pre>
              <div class="row">${buttonsHTML}</div>
            `;
            fileList.appendChild(fileDetails);
          } else {
            const errorMsg = document.createElement('p');
            errorMsg.style.color = 'red';
            errorMsg.textContent = `Error: ${data.message}`;
            fileList.appendChild(errorMsg);
          }
        } catch (error) {
          console.error('Error:', error);
          document.getElementById('fileListContent').innerHTML = 
            `<div class="alert alert-danger mt-3">Network error occurred</div>`;
        }
      });   
        
});


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

$(document).on('click', '#edit', function(e) {
    e.preventDefault();
    // 先获取 filename
    const filename = document.getElementById('filename').value.trim();
    openEditor(filename);
});
