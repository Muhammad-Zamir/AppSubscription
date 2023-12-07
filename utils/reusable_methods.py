import array
import ast
import datetime
import random
import jwt
from cryptography.fernet import Fernet
from rest_framework.response import Response
from rest_framework.utils.serializer_helpers import ReturnList
import pytz
from app_subscription import settings


def create_response(data, message, status_code):
    result = {
        "status_code": status_code,
        "message": message,
        "data": data
    }
    return Response(result, status=status_code)


def get_query_param(request, key, default):
    """
    @param request: request object
    @type request: request
    @param key: key to get data from
    @type key: str
    @param default: default variable to return if key is empty or doesn't exist
    @type default: str/None
    @return: key
    @rtype: str/None
    """
    if key in request.query_params:
        key = request.query_params.get(key)
        if key:
            return key
    return default


def generate_six_length_random_number():
    random_number = random.SystemRandom().randint(100000, 999999)
    return random_number


def generate_dummy_password():
    global temp_pass_list
    MAX_LEN = 8

    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']

    UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']

    SYMBOLS = ['@', '#', '$', '%', '*']
    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS
    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    for x in range(MAX_LEN - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)

    password = ""
    for x in temp_pass_list:
        password = password + x

    return password


def decrypt_token(encrypted_token):
    """Decrypt the encrypted token string to get the original jwt token

    Args:
        encrypted_token ([str]): [The encrypted jwt token string]

    Returns:
        [str]: [The jwt token]
    """

    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.decrypt(encrypted_token.encode()).decode()


def encrypt_token(token):
    """Encrypt the jwt token so users cannot see token content

    Args:
        token ([str]): [The jwt token]

    Returns:
        [str]: [The encrypted jwt token string]
    """
    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.encrypt(token.encode()).decode("utf-8")


def generate_access_token(user):
    # nbf: Defines the time before which the JWT MUST NOT be accepted for processing
    access_token_payload = {
        'email': user.email,
        'iat': datetime.datetime.utcnow(),
        # 'role': users.role
    }
    exp_claim = {
        "exp": access_token_payload.get("iat") + datetime.timedelta(seconds=int(settings.JWT_TOKEN_EXPIRY_DELTA))}
    # Add expiry claim to token_payload
    token_payload = {**access_token_payload, **exp_claim}
    encoded_token = jwt.encode(token_payload, settings.JWT_ENCODING_SECRET_KEY, algorithm='HS256')
    jwt_token = encrypt_token(encoded_token)
    return jwt_token


def get_first_error_message_from_serializer_errors(serialized_errors, default_message=""):
    if not serialized_errors:
        return default_message
    try:

        serialized_error_dict = serialized_errors

        # ReturnList of serialized_errors when many=True on serializer
        if isinstance(serialized_errors, ReturnList):
            serialized_error_dict = serialized_errors[0]

        serialized_errors_keys = list(serialized_error_dict.keys())
        # getting first error message from serializer errors
        try:
            message = serialized_error_dict[serialized_errors_keys[0]][0].replace("This", serialized_errors_keys[0])
            return message
        except:
            return serialized_error_dict[serialized_errors_keys[0]][0]

    except Exception as e:
        # logger.error(f"Error parsing serializer errors:{e}")
        return default_message


def get_params(name, instance, kwargs):
    instance = check_for_one_or_many(instance)
    if type(instance) == list or type(instance) == tuple:
        kwargs[f"{name}__in"] = instance
    else:
        kwargs[f"{name}"] = instance

    return kwargs


def check_for_one_or_many(instances):
    try:
        instance = ast.literal_eval(instances)
        return instance
    except Exception as e:
        print(e)
        return instances


def seacrh_text_parser(text: str, kwargs: dict, prefix: str = "") -> dict:
    try:
        if len(text.split()) > 1:
            kwargs[f"{prefix}first_name__icontains"] = text.split()[0]
            kwargs[f"{prefix}last_name__icontains"] = text.split()[1]
        else:
            kwargs[f"{prefix}first_name__icontains"] = text
            kwargs[f"{prefix}last_name__icontains"] = text

        return kwargs
    except Exception as e:
        print(e)
        return kwargs


def seacrh_text_parser2(text: str, kwargs: dict, prefix: str = "") -> dict:
    try:
        if len(text.split()) > 1:
            kwargs[f"category__name__icontains"] = text.split()[0]
            kwargs[f"subcategory__name__icontains"] = text.split()[1]
            kwargs[f"category__nature__icontains"] = text.split()[1]
            kwargs[f"subcategory__nature__icontains"] = text.split()[1]

        else:
            kwargs[f"category__name__icontains"] = text
            kwargs[f"subcategory__name__icontains"] = text
            kwargs[f"category__nature__icontains"] = text
            kwargs[f"subcategory__nature__icontains"] = text


        return kwargs
    except Exception as e:
        print(e)
        return kwargs


def update_exisiting_user(user, role):
    try:
        user = user.first()
    except:
        pass
    password = generate_dummy_password()
    user.is_deleted = False
    user.deleted_at = None
    user.is_active = "ACTIVE"
    user.role = role
    user.set_password(password)
    user.save()
    return user, password


def parse_datetime(datetime_string):
    pakistan_tz = pytz.timezone('Asia/Karachi')
    datetime_string = datetime_string.astimezone(pakistan_tz)

    # Parse the datetime string
    datetime_obj = datetime.datetime.strptime(str(datetime_string), '%Y-%m-%d %H:%M:%S.%f%z')

    # Extract the date and time components
    date = datetime_obj.date()
    time = datetime_obj.time()

    return date, time


def generate_unique_6_digit_number():
    while True:
        # Generate a random 6-digit number
        number = random.randint(100000, 999999)
        return number
