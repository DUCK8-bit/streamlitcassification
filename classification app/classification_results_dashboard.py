import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import time
import json
import sqlite3
import os
from PIL import Image
import io
import base64

# Page config
st.set_page_config(
    page_title="Fashion Classification Results",
    page_icon="👗",
    layout="wide"
)

# Custom CSS for better styling
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
    .result-card {
        background: white;
        padding: 20px;
        border-radius: 15px;
        border: 1px solid #e0e0e0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        margin: 20px 0;
        transition: transform 0.2s ease;
    }
    .result-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.15);
    }
    .prediction-item {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        padding: 15px;
        border-radius: 10px;
        margin: 8px 0;
        border-left: 5px solid #007bff;
        transition: all 0.3s ease;
    }
    .prediction-item:hover {
        transform: translateX(5px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .confidence-high { 
        border-left-color: #28a745; 
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
    }
    .confidence-medium { 
        border-left-color: #ffc107; 
        background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
    }
    .confidence-low { 
        border-left-color: #dc3545; 
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
    }
    .timestamp {
        color: #666;
        font-size: 0.9rem;
        margin-bottom: 15px;
        padding: 8px 12px;
        background: #f8f9fa;
        border-radius: 6px;
        display: inline-block;
    }
    .image-container {
        text-align: center;
        margin: 15px 0;
        padding: 15px;
        background: #f8f9fa;
        border-radius: 10px;
    }
    .image-container img {
        max-width: 350px;
        border-radius: 12px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        transition: transform 0.3s ease;
    }
    .image-container img:hover {
        transform: scale(1.02);
    }
    .stats-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        margin: 10px 0;
    }
    .confidence-badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: bold;
        margin-left: 10px;
    }
    .badge-high { background: #28a745; color: white; }
    .badge-medium { background: #ffc107; color: black; }
    .badge-low { background: #dc3545; color: white; }
</style>
""", unsafe_allow_html=True)

def load_classification_results():
    """Load classification results from JSON file"""
    try:
        if os.path.exists('results/classification_results.json'):
            with open('results/classification_results.json', 'r') as f:
                results = json.load(f)
                return results
        return []
    except Exception as e:
        st.error(f"Error loading results: {e}")
        return []

def base64_to_image(base64_string):
    """Convert base64 string to PIL Image"""
    try:
        image_data = base64.b64decode(base64_string)
        image = Image.open(io.BytesIO(image_data))
        return image
    except Exception as e:
        st.error(f"Error converting image: {e}")
        return None

def get_confidence_color(confidence):
    """Get color class based on confidence level"""
    if confidence >= 70:
        return "confidence-high"
    elif confidence >= 40:
        return "confidence-medium"
    else:
        return "confidence-low"

def get_confidence_badge(confidence):
    """Get confidence badge class"""
    if confidence >= 70:
        return "badge-high"
    elif confidence >= 40:
        return "badge-medium"
    else:
        return "badge-low"

def get_confidence_emoji(confidence):
    """Get emoji based on confidence level"""
    if confidence >= 70:
        return "🟢"
    elif confidence >= 40:
        return "🟡"
    else:
        return "🔴"

def display_classification_result(result):
    """Display a single classification result"""
    st.markdown(f"""
    <div class="result-card">
        <div class="timestamp">📅 {result['timestamp']} | ⏱️ Processing Time: {result['processing_time']:.2f}s</div>
        <h4>Classification Result #{result['id']}</h4>
    </div>
    """, unsafe_allow_html=True)
    
    # Convert base64 image to PIL Image
    image = base64_to_image(result['image_base64'])
    
    # Display image and predictions side by side
    col1, col2 = st.columns([1, 2])
    
    with col1:
        if image:
            st.markdown("""
            <div class="image-container">
            """, unsafe_allow_html=True)
            st.image(image, caption="Uploaded Image", use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.error("Could not load image")
    
    with col2:
        st.subheader("🔍 Predictions")
        
        for i, prediction in enumerate(result['predictions']):
            confidence = prediction['confidence']
            label = prediction['label']
            color_class = get_confidence_color(confidence)
            badge_class = get_confidence_badge(confidence)
            emoji = get_confidence_emoji(confidence)
            
            st.markdown(f"""
            <div class="prediction-item {color_class}">
                <strong>{emoji} #{i+1} {label}</strong>
                <span class="confidence-badge {badge_class}">{confidence:.1f}%</span><br>
                <small>Confidence Score</small>
            </div>
            """, unsafe_allow_html=True)
            
            # Progress bar for confidence
            st.progress(confidence / 100)
            st.write("")
        
        # Show top prediction summary
        if result['predictions']:
            top_pred = result['predictions'][0]
            top_confidence = top_pred['confidence']
            top_label = top_pred['label']
            
            if top_confidence >= 70:
                st.success(f"🎯 **Primary Classification:** {top_label} ({top_confidence:.1f}% confidence)")
            elif top_confidence >= 40:
                st.info(f"🤔 **Likely Classification:** {top_label} ({top_confidence:.1f}% confidence)")
            else:
                st.warning(f"❓ **Low Confidence Classification:** {top_label} ({top_confidence:.1f}% confidence)")

def main():
    st.markdown('<h1 class="main-header">👗 Fashion Classification Results Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">View detailed results of each image classification with beautiful visualizations</p>', unsafe_allow_html=True)
    
    # Auto-refresh every 5 seconds
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = time.time()
    
    # Check if we should auto-refresh
    if time.time() - st.session_state.last_refresh > 5:
        st.session_state.last_refresh = time.time()
        st.rerun()
    
    # Sidebar for controls
    with st.sidebar:
        st.header("📊 Dashboard Controls")
        
        # Filter options
        st.subheader("🔍 Filters")
        min_confidence = st.slider("Minimum Confidence (%)", 0, 100, 0)
        
        # Sort options
        sort_by = st.selectbox("Sort by", ["Newest First", "Oldest First", "Highest Confidence", "Lowest Confidence"])
        
        # Manual refresh button
        if st.button("🔄 Refresh Results"):
            st.rerun()
        
        # Clear results button
        if st.button("🗑️ Clear All Results"):
            try:
                if os.path.exists('results/classification_results.json'):
                    os.remove('results/classification_results.json')
                st.rerun()
            except Exception as e:
                st.error(f"Error clearing results: {e}")
    
    # Load results from file
    results = load_classification_results()
    
    # Main content area
    if not results:
        st.info("📸 No classification results yet. Upload an image in your fashion classifier app to see results here!")
        
        # Show example of what results will look like
        st.subheader("📋 Example Result Format")
        st.markdown("""
        When you upload images in your fashion classifier app, you'll see results like this:
        
        - **Image**: The uploaded fashion item
        - **Predictions**: Top 3-5 classifications with confidence scores
        - **Processing Time**: How long the AI took to analyze
        - **Timestamp**: When the classification was performed
        """)
        
        # Show sample data structure
        sample_result = {
            'predictions': [
                {'label': 'Sneakers', 'confidence': 85.2},
                {'label': 'Running Shoes', 'confidence': 12.1},
                {'label': 'Athletic Footwear', 'confidence': 2.7}
            ],
            'processing_time': 2.44,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        st.json(sample_result)
        
    else:
        # Filter and sort results
        filtered_results = results.copy()
        
        # Apply confidence filter
        if min_confidence > 0:
            filtered_results = [
                result for result in filtered_results
                if any(pred['confidence'] >= min_confidence for pred in result['predictions'])
            ]
        
        # Apply sorting
        if sort_by == "Oldest First":
            filtered_results.reverse()
        elif sort_by == "Highest Confidence":
            filtered_results.sort(key=lambda x: max(pred['confidence'] for pred in x['predictions']), reverse=True)
        elif sort_by == "Lowest Confidence":
            filtered_results.sort(key=lambda x: max(pred['confidence'] for pred in x['predictions']))
        
        # Display results count
        st.subheader(f"📊 Showing {len(filtered_results)} classification results")
        
        # Display each result
        for result in filtered_results:
            display_classification_result(result)
            st.markdown("---")
        
        # Summary statistics
        if filtered_results:
            st.subheader("📈 Summary Statistics")
            
            # Calculate statistics
            total_results = len(filtered_results)
            avg_processing_time = sum(r['processing_time'] for r in filtered_results) / len(filtered_results)
            all_confidences = [pred['confidence'] for r in filtered_results for pred in r['predictions']]
            avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0
            high_confidence_count = sum(1 for r in filtered_results 
                                      for pred in r['predictions'] 
                                      if pred['confidence'] >= 70)
            medium_confidence_count = sum(1 for r in filtered_results 
                                        for pred in r['predictions'] 
                                        if 40 <= pred['confidence'] < 70)
            low_confidence_count = sum(1 for r in filtered_results 
                                     for pred in r['predictions'] 
                                     if pred['confidence'] < 40)
            
            # Display statistics in cards
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown(f"""
                <div class="stats-card">
                    <h3>📊 Total Classifications</h3>
                    <h2>{total_results}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="stats-card">
                    <h3>⚡ Avg Processing Time</h3>
                    <h2>{avg_processing_time:.2f}s</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div class="stats-card">
                    <h3>🎯 Avg Confidence</h3>
                    <h2>{avg_confidence:.1f}%</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                st.markdown(f"""
                <div class="stats-card">
                    <h3>🟢 High Confidence</h3>
                    <h2>{high_confidence_count}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            # Additional confidence breakdown
            st.subheader("🎨 Confidence Distribution")
            conf_col1, conf_col2, conf_col3 = st.columns(3)
            
            with conf_col1:
                st.markdown(f"""
                <div style="background: #d4edda; padding: 15px; border-radius: 10px; text-align: center;">
                    <h4>🟢 High Confidence (≥70%)</h4>
                    <h3>{high_confidence_count}</h3>
                    <small>{high_confidence_count/len(all_confidences)*100:.1f}% of predictions</small>
                </div>
                """, unsafe_allow_html=True)
            
            with conf_col2:
                st.markdown(f"""
                <div style="background: #fff3cd; padding: 15px; border-radius: 10px; text-align: center;">
                    <h4>🟡 Medium Confidence (40-69%)</h4>
                    <h3>{medium_confidence_count}</h3>
                    <small>{medium_confidence_count/len(all_confidences)*100:.1f}% of predictions</small>
                </div>
                """, unsafe_allow_html=True)
            
            with conf_col3:
                st.markdown(f"""
                <div style="background: #f8d7da; padding: 15px; border-radius: 10px; text-align: center;">
                    <h4>🔴 Low Confidence (<40%)</h4>
                    <h3>{low_confidence_count}</h3>
                    <small>{low_confidence_count/len(all_confidences)*100:.1f}% of predictions</small>
                </div>
                """, unsafe_allow_html=True)
    
    # Instructions
    st.markdown("---")
    st.markdown("""
    ### 💡 How to Use This Dashboard:
    
    1. **Upload images** in your fashion classifier app (http://localhost:8501)
    2. **View results** here in real-time (auto-refreshes every 5 seconds)
    3. **Filter results** using the sidebar controls
    4. **Sort results** by different criteria
    5. **Analyze performance** with summary statistics
    
    ### 🔄 Real-time Updates:
    This dashboard automatically refreshes every 5 seconds to show new results.
    Upload new images to see more results appear here!
    """)

if __name__ == "__main__":
    main() 