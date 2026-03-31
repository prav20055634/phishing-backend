import os
import sys

def create_file(filename, content):
    """Create file with given content"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Created: {filename}")

def setup_youtube_factory():
    """Create complete YouTube factory structure"""
    
    # Create folders
    folders = ['scripts', 'voices', 'videos', 'thumbnails', 'backgrounds', 'config']
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        print(f"📁 Created folder: {folder}/")
    
    # 1. requirements.txt
    requirements = """openai==0.28.0
gtts==2.3.2
moviepy==1.0.3
pillow==10.0.0
google-api-python-client==2.100.0
google-auth-oauthlib==1.0.0
google-auth-httplib2==0.1.0
python-dotenv==1.0.0
requests==2.31.0"""
    create_file("requirements.txt", requirements)
    
    # 2. topics.txt
    topics = """money habits that keep you poor
AI tools for beginners
tech news this week
business stories that inspire
side hustles that actually work
productivity hacks
investing for beginners
cryptocurrency explained
how to save money fast
passive income ideas"""
    create_file("topics.txt", topics)
    
    # 3. .env
    env = """# Get your API key from https://platform.openai.com/api-keys
OPENAI_API_KEY=your_openai_api_key_here"""
    create_file(".env", env)
    
    # 4. script_generator.py
    script_gen = '''import openai
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

class ScriptGenerator:
    def __init__(self, topics_file="topics.txt"):
        self.topics_file = topics_file
        self.topics = self.load_topics()
    
    def load_topics(self):
        try:
            with open(self.topics_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"Topics file {self.topics_file} not found. Using default topics.")
            return ["money habits", "AI tools", "tech news", "business stories"]
    
    def generate_script(self, topic):
        print(f"Generating script for: {topic}")
        
        prompt = f"""Write a 2-minute YouTube script about {topic}. 
        
Requirements:
- Style: Engaging, informative, conversational
- Structure: 
  * Hook (15 seconds) - Start with a surprising fact or question
  * Main content (90 seconds) - 3-4 key points with examples
  * Call to action (15 seconds) - Ask for likes, comments, and subscribes
- Include: 1 surprising fact, 1 practical tip that viewers can use today
- Tone: Enthusiastic but professional
- Target audience: Beginners interested in learning about {topic}

Format the script with clear sections: [HOOK], [CONTENT], [CTA]"""
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a professional YouTube script writer who creates engaging, viral-worthy content."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            script = response.choices[0].message.content
            
            # Save script
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scripts/{topic.replace(' ', '_')}_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"Topic: {topic}\\n")
                f.write(f"Generated: {datetime.now()}\\n")
                f.write("-" * 50 + "\\n\\n")
                f.write(script)
            
            print(f"✅ Script saved: {filename}")
            return filename, script
            
        except Exception as e:
            print(f"❌ Error generating script: {e}")
            return None, None
    
    def get_next_topic(self):
        """Get next topic from list and rotate"""
        if not self.topics:
            self.topics = self.load_topics()
        
        topic = self.topics.pop(0)
        self.topics.append(topic)  # Rotate to end
        
        # Save updated rotation
        with open(self.topics_file, 'w') as f:
            f.write('\\n'.join(self.topics))
        
        return topic

if __name__ == "__main__":
    generator = ScriptGenerator()
    topic = generator.get_next_topic()
    script_file, script = generator.generate_script(topic)'''
    create_file("script_generator.py", script_gen)
    
    # 5. voice_generator.py
    voice_gen = '''from gtts import gTTS
import os
from datetime import datetime

class VoiceGenerator:
    def __init__(self, language='en', tld='com'):
        self.language = language
        self.tld = tld  # 'com' for US English, 'co.uk' for British, etc.
        os.makedirs('voices', exist_ok=True)
    
    def text_to_speech(self, text, output_filename, slow=False):
        """Convert text to speech and save as MP3"""
        try:
            tts = gTTS(text=text, lang=self.language, slow=slow, tld=self.tld)
            output_path = f"voices/{output_filename}.mp3"
            tts.save(output_path)
            print(f"✅ Audio saved: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ Error generating speech: {e}")
            return None
    
    def create_voiceover(self, script_file):
        """Read script file and create voiceover"""
        try:
            with open(script_file, 'r') as f:
                script_text = f.read()
            
            script_text = script_text.replace('[HOOK]', '').replace('[CONTENT]', '').replace('[CTA]', '')
            
            # Split into smaller chunks
            chunks = self.split_into_sentences(script_text)
            
            audio_files = []
            base_name = os.path.basename(script_file).replace('.txt', '')
            
            for i, chunk in enumerate(chunks):
                if chunk.strip():
                    filename = f"{base_name}_part{i}"
                    audio_path = self.text_to_speech(chunk, filename)
                    if audio_path:
                        audio_files.append(audio_path)
            
            return audio_files
        except Exception as e:
            print(f"❌ Error creating voiceover: {e}")
            return []
    
    def split_into_sentences(self, text, max_chars=1000):
        """Split text into chunks at sentence boundaries"""
        sentences = text.replace('!', '.').replace('?', '.').split('.')
        chunks = []
        current_chunk = ""
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
                
            if len(current_chunk) + len(sentence) < max_chars:
                current_chunk += sentence + ". "
            else:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = sentence + ". "
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks

if __name__ == "__main__":
    generator = VoiceGenerator()
    script_files = os.listdir('scripts')
    if script_files:
        generator.create_voiceover(f"scripts/{script_files[0]}")'''
    create_file("voice_generator.py", voice_gen)
    
    # 6. video_generator.py
    video_gen = '''from moviepy.editor import *
import os
import random

class VideoGenerator:
    def __init__(self, background_dir="backgrounds"):
        self.background_dir = background_dir
        os.makedirs(background_dir, exist_ok=True)
        os.makedirs('videos', exist_ok=True)
    
    def get_background_video(self):
        """Get a random background video from the backgrounds folder"""
        try:
            videos = [f for f in os.listdir(self.background_dir) 
                     if f.endswith(('.mp4', '.mov', '.avi', '.mkv'))]
            if videos:
                return os.path.join(self.background_dir, random.choice(videos))
            return None
        except:
            return None
    
    def combine_audio_files(self, audio_files):
        """Combine multiple audio files into one"""
        try:
            audio_clips = []
            for audio_file in audio_files:
                if os.path.exists(audio_file):
                    clip = AudioFileClip(audio_file)
                    audio_clips.append(clip)
            
            if audio_clips:
                return concatenate_audioclips(audio_clips)
            return None
        except Exception as e:
            print(f"❌ Error combining audio: {e}")
            return None
    
    def create_video(self, audio_files, output_filename):
        """Create video with audio and background"""
        try:
            print("🎬 Creating video...")
            
            final_audio = self.combine_audio_files(audio_files)
            if not final_audio:
                print("❌ No audio files to process")
                return None
            
            total_duration = final_audio.duration
            print(f"Audio duration: {total_duration:.2f} seconds")
            
            # Get background video
            background_path = self.get_background_video()
            
            if background_path:
                bg_clip = VideoFileClip(background_path)
                if bg_clip.duration < total_duration:
                    bg_clip = bg_clip.loop(duration=total_duration)
                else:
                    bg_clip = bg_clip.subclip(0, total_duration)
                bg_clip = bg_clip.resize(height=1080)
                if bg_clip.w < 1920:
                    bg_clip = bg_clip.margin(left=(1920 - bg_clip.w)//2, 
                                            right=(1920 - bg_clip.w)//2, 
                                            color=(0,0,0))
            else:
                bg_clip = ColorClip(size=(1920, 1080), color=(40, 40, 40), 
                                   duration=total_duration)
            
            final_video = CompositeVideoClip([bg_clip])
            final_video = final_video.set_audio(final_audio)
            
            output_path = f"videos/{output_filename}.mp4"
            
            print("Exporting video (this may take a few minutes)...")
            final_video.write_videofile(
                output_path, 
                codec='libx264', 
                audio_codec='aac', 
                fps=24,
                threads=4,
                preset='medium'
            )
            
            final_video.close()
            bg_clip.close()
            
            print(f"✅ Video created: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"❌ Error creating video: {e}")
            return None

if __name__ == "__main__":
    generator = VideoGenerator()
    audio_files = [f"voices/{f}" for f in os.listdir('voices') if f.endswith('.mp3')]
    if audio_files:
        generator.create_video(audio_files[:2], "test_video")'''
    create_file("video_generator.py", video_gen)
    
    # 7. thumbnail_generator.py
    thumb_gen = '''from PIL import Image, ImageDraw, ImageFont
import os
import random

class ThumbnailGenerator:
    def __init__(self):
        self.width = 1280
        self.height = 720
        os.makedirs('thumbnails', exist_ok=True)
    
    def create_gradient_background(self, color1, color2):
        img = Image.new('RGB', (self.width, self.height), color=color1)
        draw = ImageDraw.Draw(img)
        for i in range(self.height):
            ratio = i / self.height
            r = int(color1[0] * (1 - ratio) + color2[0] * ratio)
            g = int(color1[1] * (1 - ratio) + color2[1] * ratio)
            b = int(color1[2] * (1 - ratio) + color2[2] * ratio)
            draw.line([(0, i), (self.width, i)], fill=(r, g, b))
        return img
    
    def create_thumbnail(self, title, output_filename):
        try:
            print(f"🖼️ Creating thumbnail for: {title}")
            
            colors = [
                ((255, 69, 0), (255, 140, 0)),
                ((0, 255, 255), (0, 128, 128)),
                ((255, 0, 255), (128, 0, 128)),
            ]
            color1, color2 = random.choice(colors)
            
            img = self.create_gradient_background(color1, color2)
            draw = ImageDraw.Draw(img)
            
            try:
                font = ImageFont.truetype("arial.ttf", 80)
                small_font = ImageFont.truetype("arial.ttf", 40)
            except:
                font = ImageFont.load_default()
                small_font = ImageFont.load_default()
            
            words = title.split()
            lines = []
            current_line = []
            for word in words:
                current_line.append(word)
                if len(' '.join(current_line)) > 20:
                    if len(current_line) > 1:
                        lines.append(' '.join(current_line[:-1]))
                        current_line = [word]
                    else:
                        lines.append(' '.join(current_line))
                        current_line = []
            if current_line:
                lines.append(' '.join(current_line))
            
            y_position = 150
            for line in lines[:3]:
                text_width = len(line) * 40
                x_position = (self.width - text_width) // 2
                draw.text((x_position, y_position), line, fill='white', font=font)
                y_position += 100
            
            button_y = self.height - 150
            button_width = 300
            button_height = 60
            button_x = (self.width - button_width) // 2
            
            draw.rectangle([button_x, button_y, button_x + button_width, button_y + button_height], 
                          fill='red', outline='white', width=3)
            draw.text((button_x + 50, button_y + 15), "WATCH NOW", fill='white', font=small_font)
            
            output_path = f"thumbnails/{output_filename}.png"
            img.save(output_path, "PNG", quality=95)
            print(f"✅ Thumbnail saved: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"❌ Error creating thumbnail: {e}")
            return None

if __name__ == "__main__":
    generator = ThumbnailGenerator()
    generator.create_thumbnail("How to Make Money Online", "test_thumbnail")'''
    create_file("thumbnail_generator.py", thumb_gen)
    
    # 8. main.py
    main_py = '''import os
from datetime import datetime
import time
from script_generator import ScriptGenerator
from voice_generator import VoiceGenerator
from video_generator import VideoGenerator
from thumbnail_generator import ThumbnailGenerator

class YouTubeFactory:
    def __init__(self):
        print("=" * 50)
        print("🎥 YouTube Automation Factory Starting...")
        print("=" * 50)
        
        self.script_gen = ScriptGenerator()
        self.voice_gen = VoiceGenerator()
        self.video_gen = VideoGenerator()
        self.thumb_gen = ThumbnailGenerator()
        
        print("✅ All modules initialized")
        print("=" * 50)
    
    def create_video_pipeline(self, topic):
        """Run complete pipeline for one topic"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{topic.replace(' ', '_')}_{timestamp}"
        
        print(f"\\n🎯 Processing: {topic}")
        print("-" * 30)
        
        # Step 1: Generate script
        print("📝 Step 1/4: Generating script...")
        script_file, script_text = self.script_gen.generate_script(topic)
        if not script_file:
            print("❌ Script generation failed")
            return None
        
        # Step 2: Create voiceover
        print("🎤 Step 2/4: Creating voiceover...")
        audio_files = self.voice_gen.create_voiceover(script_file)
        if not audio_files:
            print("❌ Voice generation failed")
            return None
        
        # Step 3: Create video
        print("🎬 Step 3/4: Creating video...")
        video_file = self.video_gen.create_video(audio_files, base_name)
        if not video_file:
            print("❌ Video creation failed")
            return None
        
        # Step 4: Create thumbnail
        print("🖼️ Step 4/4: Creating thumbnail...")
        thumbnail_file = self.thumb_gen.create_thumbnail(topic, base_name)
        
        print(f"\\n✅ Pipeline complete!")
        print(f"📁 Script: {script_file}")
        print(f"📁 Video: {video_file}")
        print(f"📁 Thumbnail: {thumbnail_file}")
        
        return {
            "topic": topic,
            "script": script_file,
            "video": video_file,
            "thumbnail": thumbnail_file
        }
    
    def run_daily(self, num_videos=1):
        """Run automation for multiple videos"""
        print(f"\\n🚀 Starting daily run: {num_videos} video(s)")
        
        results = []
        for i in range(num_videos):
            print(f"\\n📹 Video {i+1} of {num_videos}")
            topic = self.script_gen.get_next_topic()
            result = self.create_video_pipeline(topic)
            if result:
                results.append(result)
            
            if i < num_videos - 1:
                print("\\n⏳ Waiting 10 seconds before next video...")
                time.sleep(10)
        
        print("\\n" + "=" * 50)
        print(f"✅ Successfully created: {len(results)}/{num_videos} videos")
        print("=" * 50)
        
        return results

if __name__ == "__main__":
    factory = YouTubeFactory()
    factory.run_daily(num_videos=1)'''
    create_file("main.py", main_py)
    
    print("\n" + "=" * 50)
    print("🎉 SETUP COMPLETE!")
    print("=" * 50)
    print("\nNext steps:")
    print("1. Install requirements: pip install -r requirements.txt")
    print("2. Add your OpenAI API key to .env file")
    print("3. Download background videos to 'backgrounds/' folder")
    print("4. Run: python main.py")
    print("\nYour YouTube factory is ready! 🚀")

if __name__ == "__main__":
    setup_youtube_factory()