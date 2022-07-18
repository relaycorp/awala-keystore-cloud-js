const mainJestConfig = require('../../jest.config');

module.exports = {
  preset: mainJestConfig.preset,
  roots: ['.'],
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv,
};
