<?php

	Class extension_encrypted_input extends Extension{

		public function install() {
			// create suitable salt
			$key = openssl_random_pseudo_bytes(8);
			$saved = Symphony::Configuration()->set('key',$key, 'encrypted_input');

			Symphony::Configuration()->write();
			// create settings table
			return Symphony::Database()->query("CREATE TABLE `tbl_fields_encrypted_input` (
			  `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
			  `field_id` INT(11) UNSIGNED NOT NULL,
			  PRIMARY KEY  (`id`),
			  UNIQUE KEY `field_id` (`field_id`)
			) TYPE=MyISAM");
		}

		public function uninstall() {
			// remove config
			Symphony::Configuration()->remove('encrypted_input');
			Symphony::Configuration()->write();
			// remove field settings
			Symphony::Database()->query("DROP TABLE `tbl_fields_encrypted_input`");
		}

		public function getSubscribedDelegates() {
			return array(
				array(
					'page' => '/system/preferences/',
					'delegate' => 'AddCustomPreferenceFieldsets',
					'callback' => 'appendPreferences'
				),
				array(
					'page'		=> '/backend/',
					'delegate'	=> 'InitaliseAdminPageHead',
					'callback'	=> 'initaliseAdminPageHead'
				)
			);
		}

		public function initaliseAdminPageHead($context) {
			$page = Administration::instance()->Page;
			$callback = Administration::instance()->getPageCallback();

			if ($page instanceOf contentPublish && in_array($callback['context']['page'], array('edit', 'new'))) {
				Administration::instance()->Page->addScriptToHead(URL . '/extensions/encrypted_input/assets/encrypted_input.publish.js', 300);
			}
		}

		public function appendPreferences($context) {
			$group = new XMLElement('fieldset');
			$group->setAttribute('class', 'settings');
			$group->appendChild(new XMLElement('legend', __('Encrypted Input')));

			$label = Widget::Label(__('Key'));
			$input = Widget::Input('settings[encrypted_input][key]', Symphony::Configuration()->get('key', 'encrypted_input'));
			$label->appendChild($input);
			$group->appendChild($label);

			$context['wrapper']->appendChild($group);
		}

	}
