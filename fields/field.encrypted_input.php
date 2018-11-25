<?php

	Class FieldEncrypted_Input extends Field {

		function __construct(){
			parent::__construct();
			$this->_name = 'Encrypted Input';
			$this->_required = true;
			$this->iv_num_bytes = 16;
			$this->hash_algo = 'sha256';
			$this->cipher_algo = 'aes-256-ctr';
			$this->key = Symphony::Configuration()->get('key','encrypted_input');
			$this->set('required', 'yes');
		}

		public function commit(){
			if(!parent::commit()) return false;

			$id = $this->get('id');
			if($id === false) return false;

			$fields = array();
			$fields['field_id'] = $id;

			Symphony::Database()->query("DELETE FROM `tbl_fields_".$this->handle()."` WHERE `field_id` = '$id' LIMIT 1");
			return Symphony::Database()->insert($fields, 'tbl_fields_' . $this->handle());
		}

		public function displaySettingsPanel(XMLElement &$wrapper, $errors = null) {
			parent::displaySettingsPanel($wrapper, $errors);

			$div = new XMLElement('div', null, array('class' => 'compact'));
			$this->appendRequiredCheckbox($div);
			$wrapper->appendChild($div);
		}

		public function displayPublishPanel(XMLElement &$wrapper, $data = null, $flagWithError = null, $fieldnamePrefix = null, $fieldnamePostfix = null, $entry_id = null){
			$value = General::sanitize(base64_encode($data['value']));
			$label = Widget::Label($this->get('label'));

			if(empty($value)) {
			    if($this->get('required') != 'yes') $label->appendChild(new XMLElement('i', __('Optional')));
			    $label->appendChild(Widget::Input('fields'.$fieldnamePrefix.'['.$this->get('element_name').']'.$fieldnamePostfix, (strlen($value) != 0 ? $value : null)));
			    if($flagWithError != null) {
			        $wrapper->appendChild(Widget::Error($label, $flagWithError));
			    } else {
			        $wrapper->appendChild($label);
			    }
			} else {
				$wrapper->setAttribute('class', $wrapper->getAttribute('class') . ' file');
			    $label->appendChild(new XMLElement('span', 'Encrypted: ' . $value, array('class' => 'frame')));
			    $label->appendChild(Widget::Input('fields'.$fieldnamePrefix.'['.$this->get('element_name').']'.$fieldnamePostfix, 'encrypted:' . $value, 'hidden'));
			    $wrapper->appendChild($label);
			}

		}

		public function appendFormattedElement(XMLElement &$wrapper, $data, $encode = false, $mode = null, $entry_id = null){
			if(!is_array($data) || empty($data['value'])) return;

			$value = $this->decrypt($data['value']);

			$xml = new XMLElement($this->get('element_name'), General::sanitize($value));
			$wrapper->appendChild($xml);
		}

		public function checkPostFieldData($data, &$message, $entry_id = null){
			$message = null;

			if($this->get('required') === 'yes' && strlen($data) == 0){
				$message = __("'%s' is a required field.", array($this->get('label')));
				return self::__MISSING_FIELDS__;
			}

			return self::__OK__;
		}

		public function processRawFieldData($data, &$status, &$message = null, $simulate = false, $entry_id = null) {
			$status = self::__OK__;

			// store empty (null) value without encryption if the field is optional
			if(empty($data)) return array('value' => '');

			// has already been encrypted
			if(preg_match("/^encrypted:/", $data)) {
				$data = preg_replace("/^encrypted:/", '', $data);
			    return array(
    				'value' => base64_decode($data),
    			);
			}
			else {
			    return array(
    				'value' => $this->encrypt($data),
    			);
			}

		}

		function encrypt($string) {

			// Build an initialisation vector
	        $iv = openssl_random_pseudo_bytes($this->iv_num_bytes, $isStrongCrypto);
	        if (!$isStrongCrypto) {
	            throw new \Exception("Cryptor::encryptString() - Not a strong key");
	        }
	        // Hash the key
	        $keyhash = openssl_digest($this->key, $this->hash_algo, true);
	        // and encrypt
	        $opts =  OPENSSL_RAW_DATA;
	        $encrypted = openssl_encrypt($string, $this->cipher_algo, $keyhash, $opts, $iv);
	        if ($encrypted === false)
	        {
	            throw new \Exception('Cryptor::encryptString() - Encryption failed: ' . openssl_error_string());
	        }
	        // The result comprises the IV and encrypted data
	        $res = $iv . $encrypted;

	        return $res;
		}

		function decrypt($raw) {

			// and do an integrity check on the size.
	        if (strlen($raw) < $this->iv_num_bytes)
	        {
	            throw new \Exception('Cryptor::decryptString() - ' .
	                'data length ' . strlen($raw) . " is less than iv length {$this->iv_num_bytes}");
	        }
	        // Extract the initialisation vector and encrypted data
	        $iv = substr($raw, 0, $this->iv_num_bytes);
	        $raw = substr($raw, $this->iv_num_bytes);
	        // Hash the key
	        $keyhash = openssl_digest($this->key, $this->hash_algo, true);
	        // and decrypt.
	        $opts = OPENSSL_RAW_DATA;
	        $res = openssl_decrypt($raw, $this->cipher_algo, $keyhash, $opts, $iv);
	        if ($res === false)
	        {
	            throw new \Exception('Cryptor::decryptString - decryption failed: ' . openssl_error_string());
	        }
	        return $res;

	    }


		function decrypt_legacy($string) {
			return trim(
				mcrypt_decrypt(
					MCRYPT_RIJNDAEL_256,
					hash('sha256', Symphony::Configuration()->get('salt', 'encrypted_input'), true),
					base64_decode($string),
					MCRYPT_MODE_ECB,
					mcrypt_create_iv(
						mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB),
						MCRYPT_RAND
					)
				)
			);
		}

	}
