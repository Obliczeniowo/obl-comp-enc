#!/usr/bin/env node

/**
 * Batch Encrypt/Decrypt Script (Recursive with Output Path & Password Prompt)
 * --------------------------------------------------------------------------
 * Reads a config JSON file containing an array of jobs.
 * If a job has no password, prompts the user and validates it.
 *
 * Password rules:
 *   - At least 1 digit
 *   - At least 1 special character
 *   - At least 1 lowercase
 *   - At least 1 uppercase
 *   - Minimum length: 10
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as readline from 'readline';

function askPassword(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });

    rl.question(promptText, (password) => {
      rl.close();
      resolve(password);
    });
  });
}

function validatePassword(password) {
  const errors = [];
  if (password.length < 10) errors.push('Password must be at least 10 characters long.');
  if (!/[A-Z]/.test(password)) errors.push('Password must contain at least one uppercase letter.');
  if (!/[a-z]/.test(password)) errors.push('Password must contain at least one lowercase letter.');
  if (!/[0-9]/.test(password)) errors.push('Password must contain at least one digit.');
  if (!/[!@#$%^&*(),.?':{}|<>_\-\\[\]/;'+=]/.test(password)) errors.push('Password must contain at least one special character.');
  return errors;
}

function ensureDirSync(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function deriveKeyFromPassword(password, aesSize, salt) {
  const keySizeBytes = aesSize / 8;
  return crypto.pbkdf2Sync(password, salt, 100000, keySizeBytes, 'sha512');
}

function encryptFile(inputFile, outputFile, aesSize, password) {
  const algorithm = 'aes-256-cbc';
  const salt = crypto.randomBytes(16);
  const key = deriveKeyFromPassword(password, aesSize, salt);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key.slice(0, 32), iv);
  const data = fs.readFileSync(inputFile);

  if (fs.existsSync(outputFile)) {
    console.log('File exist check if same')
    try {
      const old = decryptFileContent(outputFile, aesSize, password);
      if (Buffer.compare(old, data) === 0) {
        console.log(`Encryption skipped as no changes detected: ${inputFile} -> ${outputFile}`);
        return;
      }
    } catch (error) {
      console.log(`Decryption fail on: ${outputFile} so lets encrypt with new password`);
    }
  }

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

  ensureDirSync(path.dirname(outputFile));
  fs.writeFileSync(outputFile, Buffer.concat([salt, iv, encrypted]));

  console.log(`Encrypted: ${inputFile} -> ${outputFile}`);
}

function decryptFileContent(inputFile, aesSize, password) {
  const algorithm = 'aes-256-cbc';
  const content = fs.readFileSync(inputFile);

  const salt = content.slice(0, 16);
  const iv = content.slice(16, 32);
  const encryptedData = content.slice(32);

  const key = deriveKeyFromPassword(password, aesSize, salt);
  const decipher = crypto.createDecipheriv(algorithm, key.slice(0, 32), iv);

  try {
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decrypted;
  } catch (err) {
    throw new Error(err.message);
  }
}

function decryptFile(inputFile, outputFile, aesSize, password) {
  try {
    const decrypted = decryptFileContent(inputFile, aesSize, password);
    ensureDirSync(path.dirname(outputFile));
    fs.writeFileSync(outputFile, decrypted);
    console.log(`Decrypted: ${inputFile} -> ${outputFile}`);
  } catch (err) {
    console.error(`Failed to decrypt ${inputFile}: Wrong password or corrupted file.`);
  }
}

function processFolderRecursive(inputFolder, outputFolder, mode, aesSize, password, override, exclude, copy) {
  const items = fs.readdirSync(inputFolder);
  for (const item of items) {
    if (copy.includes(item)) {
      if (!fs.existsSync(outputFolder)) {
        fs.mkdirSync(outputFolder, { recursive: true })
      }
      fs.copyFileSync(path.join(inputFolder, item), path.join(outputFolder, item));
    }
    if (exclude.includes(item)) {
      console.log('Exclude', item, exclude)
      continue;
    }
    if (item.includes('.enc') && mode === 'encrypt') {
      console.log('skip encrypt encrypted');
      continue;
    }
    const inputPath = path.join(inputFolder, item);
    const outputPath = path.join(outputFolder, item);

    if (fs.lstatSync(inputPath).isDirectory()) {
      processFolderRecursive(inputPath, outputPath, mode, aesSize, password, override, exclude, copy);
    } else if (fs.lstatSync(inputPath).isFile()) {
      if (mode === 'encrypt') {
        const outFile = `${outputPath}.enc`;
        encryptFile(inputPath, outFile, aesSize, password);
      } else if (mode === 'decrypt' && inputPath.includes('.enc')) {
        let outFile;
        if (override) {
          outFile = outputPath.replace(/\.enc/, '');
        } else {
          const originalExt = path.extname(inputPath).replace('.enc', '');
          outFile = outputPath.replace('.enc', `.dec${originalExt}`);
        }
        decryptFile(inputPath, outFile, aesSize, password);
      }
    }
  }
}

function compareFoldersContentsRecursively(inputFolder, outputFolder) {
  const items = fs.readdirSync(outputFolder);
  const exclude = ['.git']

  for (const item of items) {
    const inputPath = path.join(inputFolder, item).replace('.enc', '');
    const outputPath = path.join(outputFolder, item);
    console.log(inputPath, outputPath)
    if (!exclude.includes(item)) {
      if (fs.lstatSync(outputPath).isDirectory()) {
        compareFoldersContentsRecursively(inputPath, outputPath);
      } else if (fs.lstatSync(outputPath).isFile()) {
        if (!fs.existsSync(inputPath)) {
          console.log('remove', outputPath)
          fs.rmSync(outputPath);
        }
      }
    }
  }
}

async function runBatch(configPath) {
  if (!fs.existsSync(configPath)) {
    console.error(`Error: Config file '${configPath}' not found.`);
    process.exit(1);
  }

  let config;
  try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (err) {
    console.error('Error parsing config JSON:', err.message);
    process.exit(1);
  }

  if (!Array.isArray(config)) {
    console.error('Config file must contain an array of jobs.');
    process.exit(1);
  }

  for (let index = 0; index < config.length; index++) {
    const currentConfig = config[index];
    console.log(`\n[Job ${index + 1}] ${currentConfig.mode ? currentConfig.mode.toUpperCase() : 'UNKNOWN'} - ${currentConfig.path}`);

    if (!currentConfig.path || !currentConfig.mode) {
      console.error('Missing required fields: path, mode.');
      continue;
    }
    if (currentConfig.mode !== 'encrypt' && currentConfig.mode !== 'decrypt') {
      console.error('Mode must be "encrypt" or "decrypt".');
      continue;
    }

    let password = currentConfig.password;
    while (!password) {
      password = await askPassword('Setup password: ');
      const errors = validatePassword(password);
      if (errors.length > 0) {
        console.error('Password validation failed:');
        errors.forEach(err => console.error(`- ${err}`));
        password = null;
      }
    }

    const aesSize = currentConfig.aes && (currentConfig.aes === 256 || currentConfig.aes === 512) ? currentConfig.aes : 256;
    const override = currentConfig.override === true;
    const outputFolder = currentConfig.output ? path.resolve(currentConfig.output) : path.resolve(currentConfig.path);
    const inputFolder = path.resolve(currentConfig.path);

    if (!fs.existsSync(inputFolder) || !fs.lstatSync(inputFolder).isDirectory()) {
      console.error(`Error: '${inputFolder}' is not a valid folder.`);
      continue;
    }

    console.log('config', JSON.stringify(currentConfig, undefined, 2));

    console.log('Build check', config[index].build);
    /**
     * config.build === true means it is build version of configuration so need compare already exist one with not existing one
     * config.mode === 'encrypt' as it is for encryption only
     */
    if (config[index].build && config[index].mode === 'encrypt') {
      /** remove files if not exist inside input folder */
      try {
        compareFoldersContentsRecursively(inputFolder, outputFolder, currentConfig.exclude || []);
      } catch (error) {
        console.log(error)
        throw new Error('You must initialize build folder with git repository of builded lib ' + inputFolder + ' ' + outputFolder)
      }
    }
    processFolderRecursive(inputFolder, outputFolder, currentConfig.mode, aesSize, password, override, currentConfig.exclude || [], currentConfig.copy || []);
  }
}

// CLI usage: node batch-encdec.js [config.json]
const configFile = process.argv[2] ? process.argv[2] : 'config.json';
runBatch(configFile);
