# 引入依赖
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from phe import paillier
import json

app = Flask(__name__)
app.secret_key = '31415926'  # 设置一个秘密密钥

# 生成 Paillier 公钥和私钥
public_key, private_key = paillier.generate_paillier_keypair()

# 存储同态累加的投票总和
encrypted_total_votes = None

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 假设的用户数据结构
users = {'admin': {'password': generate_password_hash('123'), 'is_admin': True},
         'xj': {'password': generate_password_hash('123'), 'is_admin': False},
         'xd': {'password': generate_password_hash('123'), 'is_admin': False},
         'xt': {'password': generate_password_hash('123'), 'is_admin': False},
         'xa': {'password': generate_password_hash('123'), 'is_admin': False},
         'xb': {'password': generate_password_hash('123'), 'is_admin': False},
         'xc': {'password': generate_password_hash('123'), 'is_admin': False},
         'xe': {'password': generate_password_hash('123'), 'is_admin': False}
         }

voted_users = set()  # 记录已投票的用户

# 用户类
class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.is_admin = users[username]['is_admin']

def is_admin():
    # 检查当前登录的用户是否有管理员权限
    return current_user.is_authenticated and current_user.is_admin


@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return

    user = User(username)
    user.id = username
    return user

@app.route('/',methods=['GET', 'POST'])
def index():
    
    # 调用登录页面
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(request.method)
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username)
            login_user(user)
            # 根据用户类型重定向到不同的页面
            if user.is_admin:
                return redirect(url_for('admin_voting'))  # 管理员用户
            else:
                return redirect(url_for('vote'))  # 普通用户
            # return redirect(url_for('vote'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# 全局变量来存储当前投票事项的标识符
current_voting_item = None
# 存储加密的投票
encrypted_votes = []



@app.route('/admin/voting', methods=['GET', 'POST'])
@login_required
def admin_voting():
    if not is_admin():
        return "Access Denied", 403
    print(request.method)
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        # 处理创建投票事项的逻辑
        create_voting_item(title, description)
        current_voting_item = title  # 更新当前活跃的投票事项标识符
        return redirect(url_for('admin_voting'))

    return render_template('admin_voting.html')

def create_voting_item(title, description):
    # 创建投票事项并持久化存储
    # 示例：保存到文件或数据库
    with open('voting_item.txt', 'w') as file:
        file.write(f'{title}\n{description}')

# 读取配置文件voting_item.txt
def load_current_voting_item():
    try:
        with open('voting_item.txt', 'r') as file:
            title = file.readline().strip()  # 读取第一行作为标题
            return title
    except FileNotFoundError:
        return None

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    # 使用全局变量 current_voting_item
    global current_voting_item
    # 检查是否已经设置了current_voting_item，如果没有，则尝试从文件加载
    
    current_voting_item = load_current_voting_item()
    if current_voting_item is None:
        # 如果文件不存在或标题为空，则设置一个默认值
        current_voting_item = load_current_voting_item()
    print(request.method)
    return render_template('vote.html', public_key_n=str(public_key.n), voting_item=current_voting_item)

@app.route('/submit_vote', methods=['GET', 'POST'])
@login_required
def submit_vote():
    global encrypted_total_votes, voted_users
   
    if current_user.id in voted_users:
        print(f"重复投票")
        return jsonify({'status': 'error', 'message': 'You have already voted'}), 403
    print("接收到 POST 请求 /submit_vote")
    
    data = request.get_json()
    if data is None:
        print("错误：未接收到 JSON 数据")
        return jsonify({'status': 'error', 'message': 'No JSON data received'}), 400

    encrypted_vote = data.get('vote')
    if encrypted_vote is None:
        print("错误：JSON 数据中未包含 'vote'")
        return jsonify({'status': 'error', 'message': 'Missing "vote" in JSON data'}), 400

    print(f"接收到加密的投票数据: {encrypted_vote}")

    try:
        encrypted_vote_obj = paillier.EncryptedNumber(public_key, int(encrypted_vote))
    except Exception as e:
        print(f"错误：转换加密投票数据时出错 - {e}")
        return jsonify({'status': 'error', 'message': 'Error processing encrypted vote'}), 500

    print("成功转换加密投票数据")

    if encrypted_total_votes is None:
        encrypted_total_votes = encrypted_vote_obj
        print("初始化累加的投票总和")
        decrypted_total_votes = private_key.decrypt(encrypted_vote_obj) #调试用
        print(f"解密的初始投票数据: {decrypted_total_votes}") #调试用
        voted_users.add(current_user.id)
    else:
        encrypted_total_votes += encrypted_vote_obj
        print("累加到现有的投票总和")
        decrypted_total_votes = private_key.decrypt(encrypted_total_votes) #调试用
        print(f"解密的累加投票数据: {decrypted_total_votes}") #调试用
        voted_users.add(current_user.id)
    try:
        save_to_file(current_voting_item, encrypted_total_votes)
        print("累加结果已保存到文件")
        #save_private_key(private_key)
        #print("私钥已保存到文件")
        #save_public_key(public_key)
        #print("公钥已保存到文件")
        
    except Exception as e:
        print(f"错误：保存文件时出错 - {e}")
        return jsonify({'status': 'error', 'message': 'Error saving file'}), 500

    return jsonify({'status': 'success', 'message': 'Vote recorded successfully'})


def save_to_file(voting_item, encrypted_total):
    filename = f'encrypted_votes_{voting_item}.txt'
    with open(filename, 'w') as file:
        file.write(str(encrypted_total.ciphertext()))

def save_private_key(private_key, filename='private_key.json'):
    private_key_data = {'lambda': str(private_key.lambda_), 'mu': str(private_key.mu)}
    with open(filename, 'w') as file:
        json.dump(private_key_data, file)

def save_public_key(public_key, filename='public_key.json'):
    public_key_data = {'n': str(public_key.n)}
    with open(filename, 'w') as file:
        json.dump(public_key_data, file)

@app.route('/results')
@login_required
def results():
    global public_key
    global private_key
    voting_item = current_voting_item
    if not is_admin():
        return "Access Denied", 403
    
    # 为调试目的打印文件名
    print(f"Debug: The voting item file name is: {voting_item}")

    # 从文件读取累加的投票总和
    encrypted_total_votes = read_from_file(voting_item)

    # 为调试目的打印加密的投票总和
    print(f"Debug: Encrypted total votes from file: {encrypted_total_votes}")

    #public_key = load_public_key() #载入公钥
    #private_key = load_private_key() #载入私钥

    # 将字符串格式的加密总和转换回 Paillier 加密对象
    encrypted_total_obj = paillier.EncryptedNumber(public_key, int(encrypted_total_votes), 0)

    # 为调试目的打印私钥，注意这是不安全的，只应在安全环境中进行
    # print(f"Debug: Private key being used: {private_key}")

    # 使用私钥解密
    try:
        decrypted_total_votes_result = private_key.decrypt(encrypted_total_obj)
        print(f"Debug: Decrypted total votes from file: {decrypted_total_votes_result}")
    except Exception as e:
        # 如果出现异常，打印异常信息并返回错误信息
        print(f"Error during decryption: {e}")
        return str(e), 500

    return render_template('results.html', total_votes=decrypted_total_votes_result)

def read_from_file(voting_item):
    filename = f'encrypted_votes_{voting_item}.txt'
    with open(filename, 'r') as file:
        return file.read()


def load_private_key(filename='private_key.json'):
    try:
        with open(filename, 'r') as file:
            private_key_data = json.load(file)
        loaded_private_key = paillier.PrivateKey(lambda_=int(private_key_data['lambda']), 
                                                 mu=int(private_key_data['mu']), 
                                                 n=public_key.n)  # 这里假设您已经加载了公钥
        return loaded_private_key
    except FileNotFoundError:
        return None

def load_public_key(filename='public_key.json'):
    try:
        with open(filename, 'r') as file:
            public_key_data = json.load(file)
        loaded_public_key = paillier.PublicKey(n=int(public_key_data['n']))
        return loaded_public_key
    except FileNotFoundError:
        return None

if __name__ == '__main__':
    app.run(debug=True,threaded=False,host='0.0.0.0')
