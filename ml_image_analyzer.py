# إنشاء ملف جديد باسم ml_image_analyzer.py
import tensorflow as tf
# بهذا:
try:
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout
    from tensorflow.keras.preprocessing.image import ImageDataGenerator
    from tensorflow.keras.optimizers import Adam
    TENSORFLOW_AVAILABLE = True
except ImportError:
    # استخدم استيرادات keras مباشرة إذا فشل استيراد tensorflow.keras
    try:
        from keras.models import Sequential, load_model
        from keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout
        from keras.preprocessing.image import ImageDataGenerator
        from keras.optimizers import Adam
        TENSORFLOW_AVAILABLE = True
    except ImportError:
        TENSORFLOW_AVAILABLE = False
        print("تحذير: TensorFlow/Keras غير مثبت. لن يعمل تحليل تعلم الآلة.")
from tensorflow.keras.optimizers import Adam
import numpy as np
from PIL import Image
import os

class ImageMalwareDetector:
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.model = load_model(model_path)
        else:
            self.model = self.build_model()
        
    def build_model(self):
        """بناء نموذج CNN للكشف عن الصور الضارة"""
        model = Sequential([
            Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 3)),
            MaxPooling2D(2, 2),
            
            Conv2D(64, (3, 3), activation='relu'),
            MaxPooling2D(2, 2),
            
            Conv2D(128, (3, 3), activation='relu'),
            MaxPooling2D(2, 2),
            
            Flatten(),
            Dense(512, activation='relu'),
            Dropout(0.5),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='binary_crossentropy',
                     metrics=['accuracy'])
        
        return model
    
    def preprocess_image(self, image_path, target_size=(128, 128)):
        """معالجة الصورة للإدخال في النموذج"""
        img = Image.open(image_path)
        img = img.resize(target_size)
        img_array = np.array(img)
        
        # إذا كانت الصورة ذات قنوات ألفا، تحويل إلى RGB
        if img_array.shape[-1] == 4:
            img_array = img_array[:, :, :3]
        
        # إذا كانت الصورة ثنائية، تحويل إلى RGB
        if len(img_array.shape) == 2:
            img_array = np.stack([img_array] * 3, axis=-1)
            
        img_array = img_array / 255.0  # تطبيع
        img_array = np.expand_dims(img_array, axis=0)  # إضافة بُعد الدفعة
        
        return img_array
    
    def predict(self, image_path):
        """توقع ما إذا كانت الصورة ضارة"""
        try:
            processed_img = self.preprocess_image(image_path)
            prediction = self.model.predict(processed_img)[0][0]
            return prediction
        except Exception as e:
            print(f"Error in ML prediction: {e}")
            return 0.5  # قيمة محايدة في حالة الخطأ
    
    def train(self, train_dir, validation_dir, epochs=10, save_path='image_malware_model.h5'):
        """تدريب النموذج على مجموعة بيانات"""
        train_datagen = ImageDataGenerator(rescale=1./255,
                                          shear_range=0.2,
                                          zoom_range=0.2,
                                          horizontal_flip=True)
        
        validation_datagen = ImageDataGenerator(rescale=1./255)
        
        train_generator = train_datagen.flow_from_directory(
            train_dir,
            target_size=(128, 128),
            batch_size=32,
            class_mode='binary'
        )
        
        validation_generator = validation_datagen.flow_from_directory(
            validation_dir,
            target_size=(128, 128),
            batch_size=32,
            class_mode='binary'
        )
        
        history = self.model.fit(
            train_generator,
            steps_per_epoch=train_generator.samples // 32,
            epochs=epochs,
            validation_data=validation_generator,
            validation_steps=validation_generator.samples // 32
        )
        
        self.model.save(save_path)
        return history