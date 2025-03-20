from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash 
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages 
from django.http import HttpResponse,JsonResponse
from .forms import SignUpForm, EditProfileForm
from django.contrib.auth.decorators import login_required
from .models import GeneratedPassword, cipher_suite
import random
import re
import string
from zxcvbn import zxcvbn
import matplotlib.pyplot as plt
import io
import urllib.parse, base64
import json
import base64
import matplotlib.pyplot as plt
from io import BytesIO
# Function to predict password strength using ML model
def ml_model_predict(password):
    """
    Custom function to evaluate password strength even without special characters
    Returns strength status as: 'Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'
    """
    # Initialize score components
    length_score = 0
    complexity_score = 0
    pattern_score = 0
    
    # Length evaluation (0-5 points)
    if len(password) >= 16:
        length_score = 5
    elif len(password) >= 12:
        length_score = 4
    elif len(password) >= 10:
        length_score = 3
    elif len(password) >= 8:
        length_score = 2
    elif len(password) >= 6:
        length_score = 1
    
    # Complexity evaluation (0-5 points)
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    complexity_count = sum([has_lowercase, has_uppercase, has_digit, has_special])
    complexity_score = min(complexity_count + 1, 5)  # Even with 3 character types, can still be strong
    
    # Pattern evaluation (0-5 points) - check for common patterns
    # This is simplified - a real implementation would check more patterns
    is_sequential = False
    is_repeated = False
    has_keyboard_pattern = False
    
    # Check for repeated characters (e.g., "aaa")
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            is_repeated = True
            break
    
    # Check for sequential characters (e.g., "abc", "123")
    for i in range(len(password) - 2):
        if (ord(password[i+1]) == ord(password[i]) + 1 and 
            ord(password[i+2]) == ord(password[i]) + 2):
            is_sequential = True
            break
    
    pattern_deductions = sum([is_sequential, is_repeated, has_keyboard_pattern])
    pattern_score = 5 - pattern_deductions
    
    # Calculate final score
    # Higher weight on length and complexity rather than just character types
    final_score = (length_score * 0.4) + (complexity_score * 0.4) + (pattern_score * 0.2)
    
    # Map to strength categories
    if final_score >= 4.5:
        return 'Very Strong'
    elif final_score >= 3.5:
        return 'Strong'
    elif final_score >= 2.5:
        return 'Medium'
    elif final_score >= 1.5:
        return 'Weak'
    else:
        return 'Very Weak'

# Function to process name input

def process_name(name: str) -> str:
    """
    Process the input name by:
      - Removing any special characters except '@'
      - Converting to lowercase
      - Capitalizing the first letter
      - Replacing the first occurrence of 'a' (if found) with '@'
    """
    if not name:
        return ""
    # Remove any character that is not a letter or '@'
    filtered = re.sub(r"[^a-zA-Z@]", "", name)
    # Convert to lowercase and then capitalize the first letter.
    processed = filtered.lower()
    if processed:
        processed = processed[0].upper() + processed[1:]
    # Replace the first occurrence of 'a' with '@' if present.
    index_a = processed.find('a')
    if index_a != -1:
        processed = processed[:index_a] + '@' + processed[index_a+1:]
    return processed

def generate_password(name: str, number: str) -> str:
    """
    Generate a password from the processed name and number using extra randomness.
    
    Steps:
      1. Build a seed as: <ProcessedName>_<number>
      2. Insert between 2 and 4 random special characters at random positions.
      3. Randomly toggle the case for some letters.
      4. Ensure the final password is at least 12 characters long.
    """
    processed_name = process_name(name)
    # Build a seed string using an underscore as a separator.
    seed = f"{processed_name}_{number}"
    
    # Convert the seed into a list of characters.
    char_list = list(seed)
    
    # Define a list of special characters for insertion.
    specials = ['!', '$', '%', '*', '&', '@', '#', '^']
    
    # Insert a random number (2 to 4) of random special characters in random positions.
    for _ in range(random.randint(2, 4)):
        pos = random.randint(0, len(char_list))
        char_list.insert(pos, random.choice(specials))
    
    # Optionally toggle the case of some letters to add more randomness.
    for i, char in enumerate(char_list):
        if char.isalpha() and random.random() < 0.3:  # 30% chance to toggle case
            char_list[i] = char.upper() if char.islower() else char.lower()
    
    password = "".join(char_list)
    
    # Ensure the password is at least 12 characters long.
    if len(password) < 12:
        pad_chars = string.ascii_letters + string.digits
        while len(password) < 12:
            password += random.choice(pad_chars)
    
    return password

def password_generator_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        number = request.POST.get('number')
        
        if name and number:
            password = generate_password(name, number)
            
            # Evaluate the strength of the password
            result = zxcvbn(password)
            score = result.get('score', 0)
            feedback = result.get('feedback', {})
            suggestions = feedback.get('suggestions', [])
            warning = feedback.get('warning', '')
            
            # Use the custom ml_model_predict function for more accurate strength assessment
            custom_status = ml_model_predict(password)
            
            # Map strength to numeric values for visualization
            status_value_map = {
                "Very Weak": 20,
                "Weak": 40,
                "Medium": 60,
                "Strong": 80,
                "Very Strong": 100
            }
            
            # Get the status value, default to the zxcvbn score mapped to percentages if not found
            status_value = status_value_map.get(custom_status, (score + 1) * 20)
            
            # Generate a bar chart
            length = len(password)
            alphabets = sum(c.isalpha() for c in password)
            numbers = sum(c.isdigit() for c in password)
            lowercase = sum(c.islower() for c in password)
            special = sum(not c.isalnum() for c in password)
            uppercase = sum(c.isupper() for c in password)
            
            # For the component chart
            component_labels = ['Alphabets', 'Numbers', 'Lowercase', 'Uppercase', 'Special']
            component_values = [alphabets, numbers, lowercase, uppercase, special]

            plt.figure(figsize=(10, 6))
            
            # Create two subplots - one for components, one for status
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6), gridspec_kw={'width_ratios': [2, 1]})
            
            # Plot the components in the first subplot
            bars = ax1.bar(component_labels, component_values, 
                    color=['blue', 'green', 'red', 'orange', 'purple'])
            ax1.set_xlabel('Password Components')
            ax1.set_ylabel('Count')
            ax1.set_title('Password Composition Analysis')
            
            # Add value labels on top of bars
            for bar in bars:
                height = bar.get_height()
                ax1.annotate(f'{height}',
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3),  # 3 points vertical offset
                            textcoords="offset points",
                            ha='center', va='bottom')
            
            # Plot the strength status in the second subplot - as a horizontal progress bar
            strength_labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
            strength_positions = [0, 20, 40, 60, 80]
            strength_colors = ["darkred", "red", "orange", "lightgreen", "green"]
            
            # Draw empty background bar (100% width)
            ax2.barh("Strength", 100, color='lightgray', edgecolor='gray', alpha=0.3)
            
            # Draw the actual strength bar
            ax2.barh("Strength", status_value, color=strength_colors[strength_labels.index(custom_status)] 
                    if custom_status in strength_labels else 'blue')
            
            # Set the status label with percentage
            ax2.text(status_value/2, 0, f"{custom_status} ({status_value}%)", 
                    ha='center', va='center', color='black', fontweight='bold')
            
            ax2.set_xlim(0, 100)
            ax2.set_title('Password Strength Rating')
            ax2.set_xlabel('Strength (%)')
            ax2.get_yaxis().set_visible(False)  # Hide y-axis labels
            
            # Add grid lines for better readability
            ax2.grid(axis='x', linestyle='--', alpha=0.7)
            
            # Add markers for each strength level
            for i, (pos, label) in enumerate(zip(strength_positions, strength_labels)):
                ax2.axvline(x=pos, color='gray', linestyle='--', alpha=0.5)
                ax2.text(pos, -0.2, label, ha='center', va='top', fontsize=8, rotation=45)
            
            plt.tight_layout()
            
            # Save the figure
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            string = base64.b64encode(buf.read())
            chart_url = urllib.parse.quote(string)
            plt.close()

            # Store the password strength analysis results
            password_strength = {
                'length': length,
                'alphabets': alphabets,
                'numbers': numbers,
                'lowercase': lowercase,
                'uppercase': uppercase,
                'special': special,
                'score': score,
                'feedback': feedback,
                'suggestions': suggestions,
                'warning': warning,
                'status': custom_status,
                'ml_prediction': custom_status,  # Use the same custom prediction
                'chart_url': chart_url
            }

            # Store the data in the session and redirect to clear form fields
            request.session['generated_passwords'] = [password]
            request.session['password_strength'] = password_strength
            return redirect('passgen')

    generated_passwords = request.session.get('generated_passwords', [])
    password_strength = request.session.get('password_strength', None)
    
    return render(request, 'authenticate/password_generator.html', {
        'generated_passwords': generated_passwords,
        'password_strength': password_strength
    })
    
@login_required
def password_history(request):
    # Retrieve the user's password generation history
    passwords = GeneratedPassword.objects.filter(user=request.user).order_by('-created_at')
    decrypted_passwords = []
    for pw in passwords:
        try:
            decrypted_passwords.append({
                'password': cipher_suite.decrypt(pw.password).decode(),  # Decrypt the password
                'created_at': pw.created_at
            })
        except Exception as e:
            print(f"Error decrypting password: {e}")
    print(f"Decrypted Passwords: {decrypted_passwords}")  # Debug statement
    context = {
        'passwords': decrypted_passwords,
    }
    return render(request, 'authenticate/password_history.html', context)
@login_required
def test_encryption(request):
    sample_password = "TestPassword123!"
    encrypted_password = cipher_suite.encrypt(sample_password.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return HttpResponse(f"Original: {sample_password}, Encrypted: {encrypted_password}, Decrypted: {decrypted_password}")

# View: Password Generator

def check_password_strength(request):
    password_strength = None
    chart_url = None
    
    if request.method == 'POST':
        password = request.POST.get('password')
        result = zxcvbn(password)
        
        # Analyze password components
        length = len(password)
        alphabets = sum(c.isalpha() for c in password)
        numbers = sum(c.isdigit() for c in password)
        lowercase = sum(c.islower() for c in password)
        special = sum(not c.isalnum() for c in password)
        uppercase = sum(c.isupper() for c in password)
        
        # Generate a bar chart
        labels = ['Alphabets', 'Numbers', 'Lowercase', 'Uppercase', 'Special Characters']
        values = [alphabets, numbers, lowercase, uppercase, special]
        
        plt.figure(figsize=(10, 5))
        plt.bar(labels, values, color=['blue', 'green', 'red', 'orange', 'purple'])
        plt.xlabel('Password Components')
        plt.ylabel('Count')
        plt.title('Password Strength Analysis')
        
        
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        string = base64.b64encode(buf.read())
        chart_url = urllib.parse.quote(string)
        
        # Get custom strength rating that doesn't require special chars
        custom_status = ml_model_predict(password)
        
        password_strength = {
            'length': length,
            'alphabets': alphabets,
            'numbers': numbers,
            'lowercase': lowercase,
            'uppercase': uppercase,
            'special': special,
            'score': result['score'],
            'feedback': result['feedback'],
            'guesses': result['guesses'],
            'crack_times_display': result['crack_times_display'],
            'status': custom_status,
            # Add recommendations for improvement
            'recommendations': generate_recommendations(password, custom_status)
        }
    
    return render(request, 'authenticate/check_password_strength.html', 
                 {'password_strength': password_strength, 'chart_url': chart_url})

def generate_recommendations(password, status):
    """Generate specific recommendations to improve password strength"""
    recommendations = []
    
    if len(password) < 12:
        recommendations.append("Increase password length to at least 12 characters")
    
    if not any(c.isupper() for c in password):
        recommendations.append("Add uppercase letters")
    
    if not any(c.islower() for c in password):
        recommendations.append("Add lowercase letters")
    
    if not any(c.isdigit() for c in password):
        recommendations.append("Add numbers")
    
    if not any(not c.isalnum() for c in password):
        recommendations.append("Consider adding special characters for extra security")
    
    # Check for common patterns
    patterns_found = []
    
    # Check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            patterns_found.append("repeated characters")
            break
    
    # Check for sequential characters
    for i in range(len(password) - 2):
        if (ord(password[i+1]) == ord(password[i]) + 1 and 
            ord(password[i+2]) == ord(password[i]) + 2):
            patterns_found.append("sequential characters")
            break
    
    if patterns_found:
        patterns_str = ", ".join(patterns_found)
        recommendations.append(f"Avoid predictable patterns ({patterns_str})")
    
    # If already strong but could be improved
    if status in ['Strong', 'Very Strong'] and not recommendations:
        recommendations.append("Your password is already strong, but you can increase entropy by adding more random elements")
    
    return recommendations

def analyze_password(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            password = data.get("password", "")
            
            if not password:
                return JsonResponse({"error": "No password provided"}, status=400)
            
            # Analyze password strength using zxcvbn
            analysis = zxcvbn(password)
            score = analysis["score"]
            feedback = analysis["feedback"]
            
            # Get custom strength rating
            custom_status = ml_model_predict(password)
            
            # Generate Strength Graph
            fig, ax = plt.subplots(figsize=(10, 6))
            categories = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
            colors = ["darkred", "red", "orange", "lightgreen", "green"]
            
            # Create the main bars
            ax.bar(categories, [1, 2, 3, 4, 5], color=colors, alpha=0.3)
            
            # Find the index of our custom status in the categories
            try:
                status_index = categories.index(custom_status)
                # Highlight the password's score with a more prominent bar
                ax.bar(categories[status_index], 5, color=colors[status_index], alpha=0.9)
            except ValueError:
                # Fallback if status not found in categories
                ax.bar(categories[score], 5, color='blue')
            
            plt.xlabel("Strength Levels")
            plt.ylabel("Score")
            plt.title("Password Strength Analysis")
            
            # Add annotations for what makes a strong password
            textstr = "\n".join([
                "Strong Password Guidelines:",
                "✓ 12+ characters length",
                "✓ Mix of uppercase & lowercase",
                "✓ Numbers included",
                "✓ Unpredictable patterns",
                "* Special characters helpful but not required"
            ])
            props = dict(boxstyle='round', facecolor='wheat', alpha=0.4)
            ax.text(0.05, 0.95, textstr, transform=ax.transAxes, fontsize=9,
                    verticalalignment='top', bbox=props)
            
            # Save graph as base64
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.read()).decode("utf-8")
            buffer.close()
            
            # Generate specific recommendations
            recommendations = generate_recommendations(password, custom_status)
            
            return JsonResponse({
                "score": score,
                "custom_score": status_index if 'status_index' in locals() else score,
                "status": custom_status,
                "feedback": feedback,
                "recommendations": recommendations,
                "strength_graph": f"data:image/png;base64,{image_base64}"
            })
        
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    
    return JsonResponse({"error": "Invalid request method"}, status=405)



# Views for authentication
def home(request): 
    return render(request, 'authenticate/home.html', {})

def login_user(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request,('Youre logged in'))
            return redirect('home')
        else:
            messages.success(request,('Error logging in'))
            return redirect('login')
    else:
        return render(request, 'authenticate/login.html', {})

def logout_user(request):
    logout(request)
    messages.success(request,('Your now logged out'))
    return redirect('home')

def register_user(request):
    if request.method =='POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(username=username, password=password)
            login(request,user)
            messages.success(request, ('Your now registered'))
            return redirect('home')
    else:
        form = SignUpForm()
    context = {'form': form}
    return render(request, 'authenticate/register.html', context)

def edit_profile(request):
    if request.method =='POST':
        form = EditProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, ('You have edited your profile'))
            return redirect('home')
    else:
        form = EditProfileForm(instance=request.user)
    context = {'form': form}
    return render(request, 'authenticate/edit_profile.html', context)

def change_password(request):
    if request.method =='POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            messages.success(request, ('You have edited your password'))
            return redirect('home')
    else:
        form = PasswordChangeForm(user=request.user)
    context = {'form': form}
    return render(request, 'authenticate/change_password.html', context)
