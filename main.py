#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from logger import *
from pathlib import Path
import argparse
import subprocess
from shutil import copyfile
import os
from xml.dom import minidom

lib_path = Path(__file__).parent / 'res'

devnull = open(os.devnull, 'w')

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input-file', required=True, help='Input folder')
parser.add_argument('-o', '--out', required=True, help='Output APK name')
parser.add_argument('-c', '--config', required=False, help='Frida config file')
parser.add_argument('-f', '--fix', action='store_true', default=False, required=False, help='Fix 32bits only native libs in the APK, it can fix Java.lang.UnsatisfiedLinkError error')
parser.add_argument('-d', '--debug', action='store_true', default=False, required=False, help='Run in debug mode')
parser.add_argument('-ns', '--not-sign', action='store_true', default=False, required=False, help='Do not Sign APK. if you want to sign by yourself')
parser.add_argument('-a', '--arch', required=False, default='all', choices= ['all','armeabi','armeabi-v7a','arm64-v8a','x86','x86_64'], help='Arch target (depends on device version)')

args = vars(parser.parse_args())

def check_smali_path(path):
	# Check if smali/ folder is present or another name (smali_classes2/3/..)
	if os.path.isfile(path):
		return path
	else:
		# Search for another smali* fodler
		folders = os.listdir('unpacked/')
		smali_folders = []
		for fold in folders:
			if 'smali' in fold:
				new_path = path.replace('/smali/','/'+fold+'/')
				if os.path.isfile(new_path):
					return new_path
				smali_folders.append(fold)
		print_error('Couldnt locate the MainActivity in smalis dirs')
		sys.exit()
		# Check if in one of these dirs there is the correct Activiry


def get_main_act(target):
	# decode with apktool
	print_info('Decoding APK to read AndroidManifest (decoding resources)')
	subprocess.call(['apktool','d','-o','temp', target])
	# parse th file and search for main activity
	print_info('Getting MainActivity from the Android Manifest')
	xmldoc = minidom.parse('temp/AndroidManifest.xml')
	activities = xmldoc.getElementsByTagName('activity')
	activity_aliases = xmldoc.getElementsByTagName('activity-alias')

	for act in activities:
		activity_name = act.attributes['android:name'].value
		# for each activity
		intents = act.getElementsByTagName('intent-filter')
		if len(intents):
			# if at least 1 intent
			for intent in intents:
				categs = intent.getElementsByTagName('category')
				for cat in categs:
					# category example is <category android:name="android.intent.category.LAUNCHER"/>
					if 'android.intent.category.LAUNCHER'  == cat.attributes['android:name'].value:
						# if android.intent.category.LAUNCHER means this is the main activity
						print_ok(activity_name + ' is the LAUNCHER activity')
						return check_smali_path('unpacked/smali/' + activity_name.replace(".", "/") + '.smali')

	for act in activity_aliases:
		activity_name = act.attributes['android:targetActivity'].value
		# for each alias
		intents = act.getElementsByTagName('intent-filter')
		if len(intents):
			# if at least 1 intent
			for intent in intents:
				categs = intent.getElementsByTagName('category')
				for cat in categs:
					# category example is <category android:name="android.intent.category.LAUNCHER"/>
					if 'android.intent.category.LAUNCHER'  == cat.attributes['android:name'].value:
						# if android.intent.category.LAUNCHER means this is the main activity
						print_ok(activity_name + ' is the LAUNCHER activity')
						return check_smali_path('unpacked/smali/' + activity_name.replace(".", "/") + '.smali')


def inject_smali(target):
	print_info("Decoding APK")
	subprocess.call(['apktool', '-r', 'd', '-o', 'unpacked', target])
	print_debug("Reading smali file")
	main_act = get_main_act(target)
	with open(main_act, 'r') as f:
		source = f.readlines()
	#search for main
	print_debug("Looking for constructor")
	found = False
	for line in source:
		if "# direct methods" in line:
			# Generelly the contrucotr is the first method
			print_info("Injecting smali code into " + main_act)

			# We need at least to use 1 local regs so if .local 0 we can replace with .locals 1
			# TODO: check if this is correct:
			source[source.index(line)+2] = source[source.index(line)+2].replace('0','1')
			source[source.index(line)+3] = '\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
			found = True
			break
	#write on file
	print_debug("Writing new file")
	with open(main_act, 'w') as f:
		f.writelines(source)
	if found:
		print_ok('Smali injected')
	else:
		print_error('Smali NOT injected . can\' find the constructor')
		sys.exit()

def insert_frida_lib():
	# Create lib's folder if they dont exist .. and put frida-gadgets libs (for every arch)
	sub_folders = ['armeabi','arm64-v8a','armeabi-v7a','x86','x86_64']
	# Create lib folder if it doesnt exist..
	try:
		os.mkdir('unpacked/lib')
	except:
		print_debug('lib/ folder exist')

	if args['fix']:
		# a target app can have libs compiled in 32 bit and not in 64, and vice versa
		# if they are 32 bit and you include the frida-gadget on 64 bit's folder
		# it will search for these libs in this folder and fail (you cannot put 32 libs in 64 bit folder)

		print_info('Trying to fix UnsatisfyLink exception')
	else:
		# if you dont want to fix ...
		if args['arch'] == 'all':
			print_warning('Copying frida-gadgets in all libs .. if the app crash try to specify more specific arch cuz maybe app\'s libs are not for both arch.')
			# Put libfrida into all lib's dir (for all archs)
			# you have no problems if the binary has shared libs for both 32 and 64 bit
			for folder in sub_folders:
				try:
					os.mkdir('unpacked/lib/'+folder)
					print_debug('unpacked/lib/'+folder+' succesfully created')
				except Exception as ez:
					print_debug('lib/'+folder+' already exist')
					continue

			copyfile(lib_path / 'frida-gadget-16.4.8-android-arm.so','unpacked/lib//armeabi/libfrida-gadget.so')
			copyfile(lib_path / 'frida-gadget-16.4.8-android-arm.so','unpacked/lib/armeabi-v7a/libfrida-gadget.so')
			copyfile(lib_path / 'frida-gadget-16.4.8-android-arm64.so','unpacked/lib/arm64-v8a/libfrida-gadget.so')
			copyfile(lib_path / 'frida-gadget-16.4.8-android-x86.so','unpacked/lib/x86/libfrida-gadget.so')
			copyfile(lib_path / 'frida-gadget-16.4.8-android-x86_64.so','unpacked/lib/x86_64/libfrida-gadget.so')
		else:
			# Use a specific arch
			# Create lib root folder
			try:
				os.mkdir('unpacked/lib/'+args['arch']+'/')
			except:
				print_debug('folder already exist')
			# Find the right frida gadget !
			if 'arm' in args['arch']:
				if 'arm64' in args['arch']:
					t_file = 'frida-gadget-16.4.8-android-arm64.so'
				else:
					t_file = 'frida-gadget-16.4.8-android-arm.so'
			if 'x86' in args['arch']:
				t_file = 'frida-gadget-16.4.8-android-x86.so'
			if 'x86_64' in args['arch']:
				t_file = 'frida-gadget-16.4.8-android-x86_64.so'

			# Copy the frida-gadget file into appropriate lib
			copyfile(lib_path / t_file,'unpacked/lib/'+args['arch']+'/libfrida-gadget.so')

def insert_frida_config(config_file):
	# Create lib's folder if they dont exist .. and put frida-gadgets libs (for every arch)
	sub_folders = ['armeabi','arm64-v8a','armeabi-v7a','x86','x86_64']
	archfolder_template = 'unpacked/lib/{0}/libfrida-gadget.config.so'
	# Create lib folder if it doesnt exist..
	try:
		os.mkdir('unpacked/lib')
	except:
		print_debug('lib/ folder exist')

	if args['arch'] == 'all':
		print_warning('Copying frida gadgets config in all libs')
		# Put libfrida into all lib's dir (for all archs)
		# you have no problems if the binary has shared libs for both 32 and 64 bit
		for folder in sub_folders:
			try:
				os.mkdir(f'unpacked/lib/{folder}')
				print_debug(f'unpacked/lib/{folder} succesfully created')
			except:
				print_debug(f'lib/{folder} already exist')
			copyfile(config_file, archfolder_template.format(folder))

	else:
		# Use a specific arch
		# Create lib root folder
		try:
			os.mkdir('unpacked/lib/'+args['arch'])
		except:
			print_debug('folder already exist')
		# Copy the frida-gadget file into appropriate lib
		copyfile(config_file, archfolder_template.format(args['arch']))

def build_apk():
	apk_name = 'repacked.apk'
	# Build APK and Sign it
	subprocess.call(['apktool', 'b', '-o', apk_name, 'unpacked/'])
	print_ok('APK build Successfull')
	return apk_name

def zipalign_apk(apk_name):
	print_info('Using zipalign')
	subprocess.call(f'zipalign -p 4 {apk_name} repacked_aligned.apk', shell=True)
	return 'repacked_aligned.apk'

def sign_apk(apk_name, use_apksigner=True):
	cert_gen_cmd = 'keytool -genkey -keystore ssl.key -keyalg RSA -keysize 2048 -validity 10000 -alias sslpin -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown" -storepass test12 -keypass test12'
	sign_apk_cmd = f'jarsigner -sigalg SHA256withRSA -digestalg SHA-256 -keystore ssl.key -storepass test12 {apk_name} sslpin'
	if use_apksigner:
		print_info('Apksigner selected')
		sign_apk_cmd = f'apksigner sign --ks ssl.key --ks-pass pass:test12 --ks-key-alias sslpin {apk_name}'
	subprocess.call(cert_gen_cmd, shell=True)
	subprocess.call(sign_apk_cmd, shell=True)
	os.remove('ssl.key')
	if use_apksigner:
		os.remove(apk_name + '.idsig')
	print_ok('APK signed')

set_debug(args['debug'])
# apk file in inout
target = args['input_file']

print_info('Cleaning stuff if they already exists')
subprocess.call('rm -rf temp/ unpacked/ ssl.key repacked.apk',shell=True, stderr=devnull,stdout=devnull)

inject_smali(target)

print_info('Inserting frida-gadgets')
insert_frida_lib()
if args['config']:
	insert_frida_config(args['config'])
print_ok('Frida-gadgets inserted')

print_info('Building APK ..')
apk_name = build_apk()

# Using zipalign
apk_name = zipalign_apk(apk_name)

if not args['not_sign']:
	print_info('Signing APK ...')
	sign_apk(apk_name)

print_info('Cleaning stuff .. ')
if not args['debug']:
	# if debugging do not remove temp/ and unpacked. oldo ye
	subprocess.call('rm -rf temp/ unpacked/', shell=True)

os.rename(apk_name, args['out'])
devnull.close()

print_ok('''
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░▄▄▀▀▀▀▀▀▀▀▀▀▄▄█▄░░░░▄░░░░█░░░░░░░
░░░░░░█▀░░░░░░░░░░░░░▀▀█▄░░░▀░░░░░░░░░▄░
░░░░▄▀░░░░░░░░░░░░░░░░░▀██░░░▄▀▀▀▄▄░░▀░░
░░▄█▀▄█▀▀▀▀▄░░░░░░▄▀▀█▄░▀█▄░░█▄░░░▀█░░░░
░▄█░▄▀░░▄▄▄░█░░░▄▀▄█▄░▀█░░█▄░░▀█░░░░█░░░
▄█░░█░░░▀▀▀░█░░▄█░▀▀▀░░█░░░█▄░░█░░░░█░░░
██░░░▀▄░░░▄█▀░░░▀▄▄▄▄▄█▀░░░▀█░░█▄░░░█░░░
██░░░░░▀▀▀░░░░░░░░░░░░░░░░░█░▄█░░░░█░░░
██░░░░░░░░░░░░░░░░░░░░░█░░░░██▀░░░░█▄░░░
██░░░░░░░░░░░░░░░░░░░░░█░░░░█░░░░░░░▀▀█▄
██░░░░░░░░░░░░░░░░░░░░█░░░░░█░░░░░░░▄▄██
░██░░░░░░░░░░░░░░░░░░▄▀░░░░░█░░░░░░░▀▀█▄
░▀█░░░░░░█░░░░░░░░░▄█▀░░░░░░█░░░░░░░▄▄██
░▄██▄░░░░░▀▀▀▄▄▄▄▀▀░░░░░░░░░█░░░░░░░▀▀█▄
░░▀▀▀▀░░░░░░░░░░░░░░░░░░░░░░█▄▄▄▄▄▄▄▄▄██
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
''')
