import os
import json
import logging
import uuid
from flask import Flask, request, Response, jsonify, render_template, session, url_for, redirect
from flask_cors import CORS
import requests
import PyPDF2
from io import BytesIO
from authlib.integrations.flask_client import OAuth
import razorpay

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production"),
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
    GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
    GITHUB_CLIENT_ID=os.environ.get("GITHUB_CLIENT_ID"),
    GITHUB_CLIENT_SECRET=os.environ.get("GITHUB_CLIENT_SECRET"),
    RAZORPAY_KEY_ID=os.environ.get("RAZORPAY_KEY_ID"),
    RAZORPAY_KEY_SECRET=os.environ.get("RAZORPAY_KEY_SECRET"),
)

CORS(app)

# Initialize OAuth
oauth = OAuth(app)

# Initialize Razorpay client
razorpay_client = razorpay.Client(
    auth=(app.config["RAZORPAY_KEY_ID"], app.config["RAZORPAY_KEY_SECRET"])
)

# OAuth Registrations
google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

github = oauth.register(
    name='github',
    client_id=app.config["GITHUB_CLIENT_ID"],
    client_secret=app.config["GITHUB_CLIENT_SECRET"],
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Token management
TOKEN_LIMIT = 300000
tokens_used = 0

def count_tokens(text):
    """Approximate token count by splitting on spaces"""
    if not text:
        return 0
    return len(text.split()) + len(text) // 4

# Initialize OpenRouter API key
KEY = os.getenv("OPENROUTER_API_KEY")

# AI Models configuration
MODELS = {
    "logic": {"name": "Logic AI", "description": "analytical, structured, step-by-step"},
    "creative": {"name": "Creative AI", "description": "poetic, metaphorical, emotional"},
    "technical": {"name": "Technical AI", "description": "precise, technical, detail-oriented"},
    "philosophical": {"name": "Philosophical AI", "description": "deep, reflective, abstract"},
    "humorous": {"name": "Humorous AI", "description": "witty, lighthearted, engaging"}
}

SYSTEM_PROMPTS = {
    "logic": "You are Logic AI — analytical, structured, step-by-step. Provide clear, logical reasoning and systematic approaches. Break down complex problems into manageable steps and explain your reasoning clearly.",
    "creative": "You are Creative AI — poetic, metaphorical, emotional. Use imaginative language and creative perspectives. Think outside the box and provide innovative solutions with vivid descriptions.",
    "technical": "You are Technical AI — precise, technical, detail-oriented. Provide accurate, detailed, and technically sound responses, focusing on facts, specifications, and practical applications.",
    "philosophical": "You are Philosophical AI — deep, reflective, abstract. Offer profound insights, explore existential questions, and provide thoughtful, nuanced perspectives.",
    "humorous": "You are Humorous AI — witty, lighthearted, engaging. Deliver responses with humor, clever analogies, and a playful tone while remaining relevant and informative."
}

# Payment status tracking (in production use database)
payment_status = {}

# Routes
@app.route('/')
def index():
    user = session.get('user')
    payment_completed = session.get('payment_completed', False)
    return render_template('index.html', user=user, payment_completed=payment_completed)

@app.route('/payment-options')
def payment_options():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('payment_options.html')

@app.route('/create-payment', methods=['POST'])
def create_payment():
    try:
        if 'user' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        # Create Razorpay order for 1 INR
        order_data = {
            'amount': 100,  # 1 INR in paise
            'currency': 'INR',
            'receipt': f'receipt_{uuid.uuid4().hex}',
            'payment_capture': 1
        }
        
        order = razorpay_client.order.create(data=order_data)
        
        return jsonify({
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency'],
            'key_id': app.config["RAZORPAY_KEY_ID"]
        })
        
    except Exception as e:
        logger.error(f"Payment creation error: {str(e)}")
        return jsonify({'error': 'Payment creation failed'}), 500

@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    try:
        data = request.json
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')
        
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # Mark payment as completed in session
        session['payment_completed'] = True
        session['payment_id'] = razorpay_payment_id
        
        return jsonify({'status': 'success', 'message': 'Payment verified successfully'})
        
    except razorpay.errors.SignatureVerificationError as e:
        logger.error(f"Payment verification failed: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Payment verification failed'}), 400
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Payment processing error'}), 500

@app.route('/continue-without-payment', methods=['POST'])
def continue_without_payment():
    """Allow user to continue without payment"""
    session['payment_completed'] = True
    session['payment_type'] = 'free'
    return jsonify({'status': 'success', 'message': 'Continuing without payment'})

@app.route('/login/google')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    try:
        google = oauth.create_client('google')
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        session['user'] = {
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'picture': user_info.get('picture'),
            'provider': 'google'
        }
        
        logger.info(f"User logged in: {user_info.get('email')}")
        # Redirect to payment options after login
        return redirect(url_for('payment_options'))
    
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        return "Authentication failed. Please try again."

@app.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorize')
def github_authorize():
    try:
        github = oauth.create_client('github')
        token = github.authorize_access_token()
        resp = github.get('user')
        user_info = resp.json()
        
        # Get user email
        email_resp = github.get('user/emails')
        emails = email_resp.json()
        primary_email = next((email['email'] for email in emails if email['primary']), user_info.get('email'))
        
        session['user'] = {
            'name': user_info.get('name') or user_info.get('login'),
            'email': primary_email,
            'picture': user_info.get('avatar_url'),
            'provider': 'github'
        }
        
        logger.info(f"User logged in: {primary_email}")
        # Redirect to payment options after login
        return redirect(url_for('payment_options'))
    
    except Exception as e:
        logger.error(f"GitHub auth error: {str(e)}")
        return "Authentication failed. Please try again."

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('payment_completed', None)
    session.pop('payment_id', None)
    session.pop('payment_type', None)
    return redirect(url_for('index'))

# File processing
def extract_text_from_pdf(file_content):
    try:
        pdf_file = BytesIO(file_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        logger.error(f"PDF extraction error: {str(e)}")
        return None

# AI Generation using direct HTTP requests
def generate(bot_name: str, system: str, user: str, file_contents: list = None):
    global tokens_used
    if not KEY:
        yield f"data: {json.dumps({'bot': bot_name, 'error': 'OpenRouter API key not configured'})}\n\n"
        return
        
    try:
        full_user_prompt = user
        if file_contents:
            file_context = "\n\n".join(file_contents)
            full_user_prompt = f"{user}\n\nAttached files content:\n{file_context}"
        
        # Check payment status
        if not session.get('payment_completed'):
            yield f"data: {json.dumps({'bot': bot_name, 'error': 'Please complete the payment process first'})}\n\n"
            return
        
        # Approximate token counting
        system_tokens = count_tokens(system)
        user_tokens = count_tokens(full_user_prompt)
        tokens_used += system_tokens + user_tokens
        
        payload = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": full_user_prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
            "stream": True
        }
        
        headers = {
            "Authorization": f"Bearer {KEY}",
            "HTTP-Referer": request.host_url,
            "X-Title": "Pentad-Chat",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            json=payload,
            headers=headers,
            stream=True,
            timeout=60
        )
        
        if response.status_code != 200:
            error_msg = f"API error: {response.status_code} - {response.text}"
            yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"
            return
        
        bot_tokens = 0
        full_response = ""
        
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    try:
                        chunk_data = json.loads(data)
                        if 'choices' in chunk_data and chunk_data['choices']:
                            delta = chunk_data['choices'][0].get('delta', {})
                            if 'content' in delta:
                                content = delta['content']
                                full_response += content
                                bot_tokens += count_tokens(content)
                                yield f"data: {json.dumps({'bot': bot_name, 'text': content})}\n\n"
                    except json.JSONDecodeError:
                        continue
        
        tokens_used += bot_tokens
        yield f"data: {json.dumps({'bot': bot_name, 'done': True, 'tokens': tokens_used})}\n\n"
        
    except Exception as exc:
        logger.error(f"Generation error for {bot_name}: {str(exc)}")
        error_msg = f"Failed to generate response: {str(exc)}"
        yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"

@app.route("/chat", methods=["POST"])
def chat():
    try:
        # Check payment status
        if not session.get('payment_completed'):
            return jsonify(error="Please complete the payment process first"), 402
        
        data = request.json or {}
        prompt = data.get("prompt", "").strip()
        fileUrls = data.get("fileUrls", [])
        
        if not prompt and not fileUrls:
            return jsonify(error="Empty prompt and no files provided"), 400
        
        if tokens_used >= TOKEN_LIMIT:
            return jsonify(error=f"Token limit reached ({tokens_used}/{TOKEN_LIMIT})"), 429
        
        file_contents = []
        if fileUrls:
            for file_url in fileUrls:
                file_contents.append(f"File attached: {file_url}")

        def event_stream():
            generators = {}
            for key in MODELS.keys():
                generators[key] = generate(key, SYSTEM_PROMPTS[key], prompt, file_contents)
            
            active_bots = list(MODELS.keys())
            
            while active_bots:
                for bot_name in active_bots[:]:
                    try:
                        chunk = next(generators[bot_name])
                        yield chunk
                        
                        try:
                            chunk_data = json.loads(chunk.split('data: ')[1])
                            if chunk_data.get('done') or chunk_data.get('error'):
                                active_bots.remove(bot_name)
                        except:
                            pass
                            
                    except StopIteration:
                        active_bots.remove(bot_name)
                    except Exception as e:
                        logger.error(f"Stream error for {bot_name}: {str(e)}")
                        active_bots.remove(bot_name)
            
            yield f"data: {json.dumps({'all_done': True, 'tokens': tokens_used})}\n\n"

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            },
        )
    
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/asklurk", methods=["POST"])
def asklurk():
    try:
        # Check payment status
        if not session.get('payment_completed'):
            return jsonify(best="", error="Please complete the payment process first"), 402
        
        data = request.json or {}
        answers = data.get("answers", {})
        prompt = data.get("prompt", "")
        
        if not answers:
            return jsonify(best="", error="No responses to analyze"), 400
        
        if not KEY:
            return jsonify(best="", error="OpenRouter API key not configured"), 500
        
        try:
            merged_content = f"Original question: {prompt}\n\n"
            for key, response in answers.items():
                if key in MODELS:
                    merged_content += f"## {MODELS[key]['name']}:\n{response}\n\n"
            
            payload = {
                "model": "deepseek/deepseek-chat-v3.1:free",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are AskLurk - an expert AI synthesizer. Your task is to analyze responses from Logic AI, Creative AI, Technical AI, Philosophical AI, and Humorous AI to create the single best answer. Combine the logical reasoning, creative insights, technical accuracy, philosophical depth, and humorous engagement to provide a comprehensive, well-structured response that leverages the strengths of all approaches. Structure your response to be insightful, engaging, and balanced."
                    },
                    {
                        "role": "user",
                        "content": f"Please analyze these AI responses to the question: \"{prompt}\"\n\nHere are the responses:\n{merged_content}\n\nPlease provide the best synthesized answer that leverages the strengths of all AI responses:"
                    }
                ],
                "temperature": 0.3,
                "max_tokens": 1500,
            }
            
            headers = {
                "Authorization": f"Bearer {KEY}",
                "HTTP-Referer": request.host_url,
                "X-Title": "Pentad-Chat",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"API error: {response.status_code} - {response.text}")
            
            result = response.json()
            best_answer = result['choices'][0]['message']['content']
            asklurk_tokens = count_tokens(best_answer)
            global tokens_used
            tokens_used += asklurk_tokens
            
            return jsonify(best=best_answer, tokens_used=tokens_used)
            
        except Exception as e:
            logger.error(f"AskLurk error: {str(e)}")
            if answers:
                first_response = next(iter(answers.values()))
                return jsonify(best=f"Fallback - Using first response:\n\n{first_response}", error="AI synthesis failed")
            return jsonify(best="", error="No responses available for synthesis")
        
    except Exception as e:
        logger.error(f"AskLurk error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/upload", methods=["POST"])
def upload():
    """File upload endpoint - simplified for Vercel"""
    try:
        if 'files' not in request.files:
            return jsonify(urls=[], error="No files provided"), 400
        
        files = request.files.getlist('files')
        urls = []
        
        for file in files:
            if file.filename == '':
                continue
            
            # In Vercel, we can't save files permanently, so we return mock URLs
            name = f"{uuid.uuid4().hex}_{file.filename}"
            urls.append(f"/static/uploads/{name}")
        
        return jsonify(urls=urls)
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': 'File upload not available in demo'}), 500

@app.route("/tokens", methods=["GET"])
def get_tokens():
    return jsonify({
        "tokens_used": tokens_used,
        "token_limit": TOKEN_LIMIT,
        "remaining_tokens": TOKEN_LIMIT - tokens_used,
        "usage_percentage": (tokens_used / TOKEN_LIMIT) * 100
    })

@app.route("/reset-tokens", methods=["POST"])
def reset_tokens():
    global tokens_used
    tokens_used = 0
    return jsonify({"message": "Token counter reset", "tokens_used": tokens_used})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "api_key_configured": bool(KEY),
        "models_configured": len(MODELS),
        "tokens_used": tokens_used
    })

# Vercel compatibility
def create_app():
    return app

# For local development
if __name__ == '__main__':
    app.run(debug=True)
