const gulp = require("gulp");
const ts = require("gulp-typescript");
const shell = require("gulp-shell");
const path = require("path");

const DIST_FOLDER = 'dist';
const TEST_CODE_FOLDER = path.resolve(DIST_FOLDER, 'tests');

function compile(defitions) {
	var tsProject = ts.createProject('tsconfig.json');
	var tsResult = tsProject.src().pipe(tsProject());
	return tsResult[defitions ? 'dts' : 'js'].pipe(gulp.dest(DIST_FOLDER));
}

// compile all files with definitions
gulp.task('js', () => compile());
gulp.task('dts', () => compile(true));
gulp.task('compile-all', gulp.parallel('js', 'dts'));

// remove test code task
gulp.task('rm-test-code', shell.task(`rm -rf ${DIST_FOLDER}/tests`));

// build task
gulp.task('build', gulp.series('compile-all', 'rm-test-code'));

// tasks for testing
gulp.task('test', gulp.series('js',
	shell.task(`node ${DIST_FOLDER}/tests/jasmine.js ; rm -f npm-debug.log`)));

gulp.task("help", (cb) => {
	var h = `
Major tasks in this project:

 1) "build" - compiles necessary for production code.
 
 2) "test" - compiles everything and runs jasmine specs.
`;
	console.log(h);
	cb();
});
gulp.task("default", gulp.series("help"));
