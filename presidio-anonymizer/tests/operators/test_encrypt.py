from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators import OperatorType


class TestEncrypt:
    @mock.patch.object(AESCipher, "encrypt")
    def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
        self, mock_encrypt
    ):
        expected_anonymized_text = "encrypted_text"
        mock_encrypt.return_value = expected_anonymized_text

        anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

        assert anonymized_text == expected_anonymized_text

    @mock.patch.object(AESCipher, "encrypt")
    def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        self, mock_encrypt
    ):
        expected_anonymized_text = "encrypted_text"
        mock_encrypt.return_value = expected_anonymized_text

        anonymized_text = Encrypt().operate(text="text", params={"key": b'1111111111111111'})

        assert anonymized_text == expected_anonymized_text

    def test_given_verifying_an_valid_length_key_no_exceptions_raised(self):
        Encrypt().validate(params={"key": "128bitslengthkey"})

    def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised(self):
        Encrypt().validate(params={"key": b'1111111111111111'})

    def test_given_verifying_an_invalid_length_key_then_ipe_raised(self):
        with pytest.raises(
            InvalidParamError,
            match="Invalid input, key must be of length 128, 192 or 256 bits",
        ):
            Encrypt().validate(params={"key": "key"})

    def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(self):
        """Test that validate raises error for invalid key length"""
        # Arrange
        encrypt = Encrypt()
        # Use a key that's actually invalid (15 bytes instead of 16, 24, or 32)
        invalid_key = b'111111111111111'  # 15 bytes - invalid length
    
        # Act & Assert
        with pytest.raises(InvalidParamError):
            encrypt.validate(params={"key": invalid_key})

    def test_operator_name(self):
        """Test that operator_name returns 'encrypt'"""
        # Arrange
        encrypt = Encrypt()
            
        # Act & Assert
        # If operator_name is a property, it should be accessed directly
        # If it's a method, it should be called with ()
        # Let's try both approaches:
        try:
            result = encrypt.operator_name
            assert result == "encrypt"
        except:
            result = encrypt.operator_name()
            assert result == "encrypt"

    def test_operator_type(self):
        """Test that operator_type returns Anonymize"""
        # Arrange
        encrypt = Encrypt()
            
        # Act & Assert
        # If operator_type is a property, it should be accessed directly
        # If it's a method, it should be called with ()
        try:
            result = encrypt.operator_type
            assert result == OperatorType.Anonymize
        except:
            result = encrypt.operator_type()
            assert result == OperatorType.Anonymize

    @pytest.mark.parametrize("key", [
        # String keys
        "a" * 16,  # 128 bits
        "a" * 24,  # 192 bits  
        "a" * 32,  # 256 bits
        # Bytes keys
        b"a" * 16,  # 128 bits
        b"a" * 24,  # 192 bits
        b"a" * 32,  # 256 bits
    ])
    def test_valid_keys(self, key):
        """Test that validate succeeds for valid key sizes"""
        # Arrange
        encrypt = Encrypt()
        
        # Act & Assert - should not raise exception
        encrypt.validate(params={"key": key})

    # Test to cover the case where key is None (line 48)
    def test_given_none_key_then_ipe_raised(self):
        """Test that validate raises error when key is None"""
        with pytest.raises(InvalidParamError):
            Encrypt().validate(params={"key": None})

    # Test to cover the case where key is wrong type (line 48)
    def test_given_invalid_type_key_then_ipe_raised(self):
        """Test that validate raises error when key is wrong type"""
        with pytest.raises(InvalidParamError):
            Encrypt().validate(params={"key": 123})  # int instead of str/bytes