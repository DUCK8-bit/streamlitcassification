import streamlit as st
import torch
from transformers import AutoImageProcessor, AutoModelForImageClassification
from PIL import Image
import requests
import io
import time
from prometheus_client import Counter, Histogram, REGISTRY, start_http_server
import threading
from datetime import datetime
import json
import os

def get_metric(metric_type, name, documentation, **kwargs):
    try:
        # Try to unregister if already exists (for Streamlit reloads)
        REGISTRY.unregister(REGISTRY._names_to_collectors[name])
    except KeyError:
        pass
    if metric_type == "histogram":
        return Histogram(name, documentation, **kwargs)
    elif metric_type == "counter":
        return Counter(name, documentation, **kwargs)

MODEL_LOAD_TIME = get_metric("histogram", 'model_load_time_seconds', 'Time taken to load a model')
CLASSIFICATION_TIME = get_metric("histogram", 'classification_time_seconds', 'Time taken to classify an image')
REQUEST_COUNTER = get_metric("counter", 'requests_total', 'Total number of requests')
CLASSIFICATION_CONFIDENCE = get_metric("histogram", 'classification_confidence_percent', 'Distribution of classification confidence')

def start_metrics_server():
    """Start the Prometheus metrics server with error handling"""
    try:
        # Try higher port numbers that are less likely to have permission issues
        ports_to_try = [9090, 9091, 9092, 8503, 8504]
        
        for port in ports_to_try:
            try:
                start_http_server(port)
                print(f"✅ Metrics server started on port {port}")
                return  # Success, exit the function
            except OSError as e:
                if "Permission denied" in str(e) or "Address already in use" in str(e):
                    print(f"⚠️ Port {port} not available, trying next...")
                    continue
                else:
                    raise e
        
        print("⚠️ All ports failed, metrics server not started")
    except Exception as e:
        print(f"⚠️ Metrics server failed to start: {str(e)[:50]}...")

# Start metrics server in a background thread (non-blocking)
try:
    threading.Thread(target=start_metrics_server, daemon=True).start()
except Exception as e:
    print(f"⚠️ Could not start metrics server thread: {str(e)[:50]}...")

# Set page config
st.set_page_config(
    page_title="Fashion Image Classifier",
    page_icon="👗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for clean, professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        text-align: center;
        color: #1f2937;
        margin-bottom: 1rem;
    }
    .subtitle {
        text-align: center;
        color: #6b7280;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .stFileUploader > div > div > div {
        background: #f9fafb;
        border: 2px dashed #d1d5db;
        border-radius: 8px;
    }
    .upload-section {
        background: white;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #e5e7eb;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_model():
    """Load the fashion classification model from Hugging Face"""
    with MODEL_LOAD_TIME.time():
        models_to_try = [
            ("google/vit-base-patch16-224", "Vision Transformer (includes fashion categories)"),
            ("microsoft/resnet-50", "ResNet-50 model"),
            ("facebook/convnext-tiny-224", "ConvNeXt model")
        ]
        
        for model_name, description in models_to_try:
            try:
                st.info(f"Loading: {description}")
                processor = AutoImageProcessor.from_pretrained(model_name)
                model = AutoModelForImageClassification.from_pretrained(model_name)
                st.success(f"✅ Successfully loaded: {description}")
                return processor, model, model_name
            except Exception as e:
                st.warning(f"❌ Failed to load {model_name}: {str(e)[:100]}...")
                continue
    
    st.error("❌ All models failed to load. Please check your internet connection and try again.")
    return None, None, None

@CLASSIFICATION_TIME.time()
def classify_image(image, processor, model, model_name):
    """Classify the uploaded fashion image"""
    try:
        # Process the image
        inputs = processor(images=image, return_tensors="pt")
        
        # Make prediction
        with torch.no_grad():
            outputs = model(**inputs)
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        # Get top 5 predictions
        top_predictions = torch.topk(predictions, 5)
        
        results = []
        for i in range(5):
            confidence = top_predictions.values[0][i].item()
            label_id = top_predictions.indices[0][i].item()
            
            # Record confidence metric
            CLASSIFICATION_CONFIDENCE.observe(confidence * 100)
            
            # Get label based on model type
            if hasattr(model.config, 'id2label'):
                label = model.config.id2label[label_id]
            else:
                label = f"Class {label_id}"
            
            # Clean up label for better display
            label = clean_label(label, model_name)
            
            results.append({
                'label': label,
                'confidence': confidence * 100
            })
            
        return results
    except Exception as e:
        st.error(f"Error during classification: {str(e)}")
        return []

def clean_label(label, model_name):
    """Clean and format labels for professional display"""
    # Remove common prefixes and clean up
    label = label.replace('_', ' ').replace('-', ' ')
    
    # Fashion-related items mapping (without emojis for professional look)
    fashion_items = {
        'jersey': 'Jersey / Sports Shirt',
        'sweatshirt': 'Sweatshirt',
        'cardigan': 'Cardigan',
        'suit': 'Suit',
        'jean': 'Jeans',
        'sock': 'Socks',
        'running shoe': 'Running Shoes',
        'loafer': 'Loafers',
        'sandal': 'Sandals',
        'boot': 'Boots',
        'sneaker': 'Sneakers',
        'clogs': 'Clogs',
        'backpack': 'Backpack',
        'purse': 'Purse',
        'sunglasses': 'Sunglasses',
        'bow tie': 'Bow Tie',
        'scarf': 'Scarf',
        'mitten': 'Mittens',
        'baseball cap': 'Baseball Cap',
        'beanie': 'Beanie',
        'sombrero': 'Hat',
        'bathing cap': 'Swimming Cap',
        'maillot': 'Swimsuit / Maillot',
        'bikini': 'Bikini'
    }
    
    # Check for exact matches or partial matches
    label_lower = label.lower()
    for key, clean_name in fashion_items.items():
        if key in label_lower:
            return clean_name
    
    # If it contains fashion keywords
    fashion_keywords = [
        'jersey', 'sweatshirt', 'cardigan', 'suit', 'jean', 'sock', 'shoe',
        'sandal', 'boot', 'sneaker', 'loafer', 'bag', 'purse', 'backpack',
        'sunglasses', 'bow tie', 'tie', 'scarf', 'glove', 'mitten', 'hat',
        'cap', 'helmet', 'dress', 'skirt', 'shirt', 'blouse', 'jacket',
        'coat', 'vest', 'sweater', 'pullover', 'hoodie', 'pants', 'trouser',
        'maillot', 'bikini', 'swimwear'
    ]
    
    if any(keyword in label_lower for keyword in fashion_keywords):
        return label.title()
    
    # For non-fashion items, return as-is but mark as general
    return f"{label.title()}"

def display_results(results):
    """Display classification results in a clean, professional format"""
    if not results:
        st.warning("No results to display")
        return
        
    st.markdown("### Classification Results")
    
    # Show only top 3 results for cleaner display
    top_results = results[:3]
    
    for i, result in enumerate(top_results):
        confidence = result['confidence']
        label = result['label']
        
        # Remove emojis for cleaner professional look
        clean_label = label.replace('👕', '').replace('👖', '').replace('👟', '').replace('🥾', '').replace('🩴', '').replace('🎒', '').replace('👛', '').replace('🕶️', '').replace('🧣', '').replace('🧢', '').replace('👗', '').replace('🔍', '').replace('🤵', '').strip()
        
        # Color coding based on confidence
        if confidence > 70:
            color = "#28a745"
            status = "High Confidence"
        elif confidence > 40:
            color = "#ffc107" 
            status = "Medium Confidence"
        else:
            color = "#6c757d"
            status = "Low Confidence"
        
        # Professional card layout
        st.markdown(f"""
        <div style="
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid {color};
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h4 style="margin: 0; color: #333; font-weight: 600;">#{i+1} {clean_label}</h4>
                <span style="
                    background: {color};
                    color: white;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: 500;
                ">{confidence:.1f}%</span>
            </div>
            <div style="
                background: #f8f9fa;
                height: 8px;
                border-radius: 4px;
                overflow: hidden;
            ">
                <div style="
                    width: {confidence}%;
                    height: 100%;
                    background: {color};
                    border-radius: 4px;
                "></div>
            </div>
            <p style="margin: 8px 0 0 0; color: #6c757d; font-size: 12px;">{status}</p>
        </div>
        """, unsafe_allow_html=True)

# Initialize session state for storing classification results
if 'classification_results' not in st.session_state:
    st.session_state.classification_results = []

def store_classification_result(image, results, processing_time):
    """Store classification result for the dashboard"""
    # Convert image to base64 for storage
    import base64
    from io import BytesIO
    
    # Resize image to reduce file size
    img_resized = image.copy()
    img_resized.thumbnail((300, 300))
    
    # Convert to base64
    buffer = BytesIO()
    img_resized.save(buffer, format='JPEG', quality=70)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    result = {
        'id': len(st.session_state.classification_results) + 1,
        'image_base64': img_base64,
        'predictions': results,
        'processing_time': processing_time,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add to session state
    st.session_state.classification_results.insert(0, result)
    
    # Keep only last 10 results to avoid memory issues
    if len(st.session_state.classification_results) > 10:
        st.session_state.classification_results = st.session_state.classification_results[:10]
    
    # Save to file for the dashboard to read
    try:
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        # Save results to JSON file
        with open('results/classification_results.json', 'w') as f:
            json.dump(st.session_state.classification_results, f, indent=2)
    except Exception as e:
        st.error(f"Error saving results: {e}")

def main():
    # Increment request counter
    REQUEST_COUNTER.inc()

    # Header
    st.markdown('<h1 class="main-header">Fashion Classifier</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Upload an image to identify clothing and fashion items using AI</p>', unsafe_allow_html=True)
    
    # Sidebar with information
    with st.sidebar:
        st.header("About")
        st.write("""
        This application uses AI to classify fashion items in images.
        
        **Supported items:**
        • Clothing (shirts, dresses, suits)
        • Footwear (shoes, sandals, boots)
        • Accessories (bags, sunglasses)
        
        **Tips for best results:**
        • Use clear, well-lit images
        • Ensure the item is the main subject
        • Avoid cluttered backgrounds
        """)
        
        st.header("Model Information")
        if 'model_name' in locals():
            st.write(f"Currently using: **{model_name.split('/')[-1]}**")
        st.write("Powered by Hugging Face Transformers")
        
        st.header("📊 View Results Dashboard")
        st.write("See detailed classification results:")
        if st.button("Open Results Dashboard"):
            st.markdown("[Open Results Dashboard](http://localhost:8504)")
        
        # Show recent results count
        if st.session_state.classification_results:
            st.write(f"**Recent Classifications:** {len(st.session_state.classification_results)}")
    
    # Load model
    with st.spinner("Loading AI model..."):
        result = load_model()
        if result and len(result) == 3:
            processor, model, model_name = result
        else:
            processor, model, model_name = None, None, None
    
    if processor is None or model is None:
        st.error("Failed to load the classification model. Please refresh the page and try again.")
        return
    
    st.success("✅ Model loaded successfully!")
    
    # Create two columns for upload options
    col1, col2 = st.columns(2)
    
    uploaded_file = None
    
    with col1:
        st.subheader("📁 Upload Image")
        uploaded_file = st.file_uploader(
            "Choose an image file",
            type=['png', 'jpg', 'jpeg', 'webp'],
            help="Upload a clear image of a fashion item"
        )
    
    with col2:
        st.subheader("📷 Take Photo")
        camera_image = st.camera_input("Take a picture of the fashion item")
        if camera_image:
            uploaded_file = camera_image
    
    if uploaded_file is not None:
        try:
            # Display the uploaded image
            image = Image.open(uploaded_file)
            
            # Create columns for image and results
            img_col, result_col = st.columns([1, 1])
            
            with img_col:
                st.subheader("📸 Uploaded Image")
                st.image(image, caption="Fashion item to classify", use_container_width=True)
                
                # Display image info
                st.write(f"**Image size:** {image.size[0]} x {image.size[1]} pixels")
                st.write(f"**Image mode:** {image.mode}")
            
            with result_col:
                # Classify the image
                start_time = time.time()
                with st.spinner("🤖 Analyzing fashion item..."):
                    results = classify_image(image, processor, model, model_name)
                processing_time = time.time() - start_time
                
                if results:
                    display_results(results)
                    
                    # Additional insights - simplified
                    top_prediction = results[0]
                    if top_prediction['confidence'] > 70:
                        st.success(f"**Primary Classification:** {top_prediction['label'].replace('👕', '').replace('👖', '').replace('👟', '').replace('🥾', '').replace('🩴', '').replace('🎒', '').replace('👛', '').replace('🕶️', '').replace('🧣', '').replace('🧢', '').replace('👗', '').replace('🔍', '').replace('🤵', '').strip()}")
                    elif top_prediction['confidence'] > 40:
                        st.info(f"**Likely Classification:** {top_prediction['label'].replace('👕', '').replace('👖', '').replace('👟', '').replace('🥾', '').replace('🩴', '').replace('🎒', '').replace('👛', '').replace('🕶️', '').replace('🧣', '').replace('🧢', '').replace('👗', '').replace('🔍', '').replace('🤵', '').strip()}")
                    else:
                        st.warning("**Low Confidence** - Consider uploading a clearer image")
                        
                    # Store classification result
                    store_classification_result(image, results, processing_time)
                    
        except Exception as e:
            st.error(f"Error processing image: {str(e)}")
    
    else:
        # Show example when no image is uploaded
        st.info("👆 Please upload an image or take a photo to get started!")
        
        # Example images section
        st.subheader("📋 Example Categories")
        example_cols = st.columns(4)
        
        examples = [
            ("👕", "Shirts & Tops"),
            ("👔", "Formal Wear"),
            ("👟", "Sneakers & Shoes"),
            ("👗", "Dresses")
        ]
        
        for i, (emoji, category) in enumerate(examples):
            with example_cols[i]:
                st.markdown(f"""
                <div style="text-align: center; padding: 1rem; border: 2px dashed #ddd; border-radius: 10px; margin: 0.5rem 0;">
                    <div style="font-size: 2rem;">{emoji}</div>
                    <div style="font-weight: bold; margin-top: 0.5rem;">{category}</div>
                </div>
                """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()