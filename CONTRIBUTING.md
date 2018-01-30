
# How to contribute to Codecrypt?

1. Fork and add a feature or a correction
2. Check that the feature/correction is applicable (see below)
3. Check that the code is in a good shape (also below)
4. Send pull request
5. Profit

### Applicable features

- All cryptography should be post-quantum (this mainly removes group-based
  asymmetric primitives)
- The program is strictly off-line, almost-non-interactive, commandline only
- Algorithms that are not mainstream are better
- Less code is always better
- Less magic is always better

### Good shape of the code

- Compile with `-Wall`
- Format the code using `astyle --style=linux -xl -xk -pdtLnU -M80`
- Try to follow similar naming conventions as the rest of the project
- Automated memory management is always better
- Use a modern C++ (unlike what codecrypt started with)
